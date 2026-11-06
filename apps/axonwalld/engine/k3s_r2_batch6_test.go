package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Round-2 batch 6 (daemon mediums) regression tests for A-M15: K3s
// ApplyConfig / ApplyVowConfig must return write and restart failures
// instead of nil, and an empty VOW manifests field must withdraw the
// stale manifest.

// installFakeK3sPath prepends a directory containing fake `systemctl`
// and `sysctl` executables to PATH. systemctl logs its invocations
// and exits with the given status; sysctl always exits 0.
func installFakeK3sPath(t *testing.T, systemctlExit int) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "systemctl-args.log")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"exit " + strconv.Itoa(systemctlExit) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write fake systemctl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sysctl"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("Failed to write fake sysctl: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

// redirectK3sPaths points the K3s filesystem roots at temp dirs and
// returns them (etc, manifests, state, vow).
func redirectK3sPaths(t *testing.T) (etcDir, manifestDir, stateDir, vowDir string) {
	t.Helper()
	origE, origM, origS, origV := k3sEtcDir, k3sServerManifestDir, k3sStateDir, vowEtcDir
	etcDir, manifestDir, stateDir, vowDir = t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	k3sEtcDir, k3sServerManifestDir, k3sStateDir, vowEtcDir = etcDir, manifestDir, stateDir, vowDir
	t.Cleanup(func() {
		k3sEtcDir, k3sServerManifestDir, k3sStateDir, vowEtcDir = origE, origM, origS, origV
	})
	return etcDir, manifestDir, stateDir, vowDir
}

const r2ValidK3sManifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: k3s-test\n"

func r2K3sBundleJSON(t *testing.T, bundle K3sRuntimeBundle) []byte {
	t.Helper()
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("failed to marshal k3s bundle: %v", err)
	}
	return raw
}

func r2VowBundleJSON(t *testing.T, bundle VowRuntimeBundle) []byte {
	t.Helper()
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("failed to marshal VOW bundle: %v", err)
	}
	return raw
}

// M15: the happy path writes the config and both manifests and
// restarts k3s.
func TestR2Batch6K3sApplyWritesFilesAndRestarts(t *testing.T) {
	logPath := installFakeK3sPath(t, 0)
	etcDir, manifestDir, _, _ := redirectK3sPaths(t)
	mgr := NewK3sManager()

	raw := r2K3sBundleJSON(t, K3sRuntimeBundle{
		Enabled:               true,
		K3sConfigYaml:         "node-name: test-node\n",
		OpenEbsManifestYaml:   r2ValidK3sManifest,
		WorkloadsManifestYaml: r2ValidK3sManifest,
	})
	if err := mgr.ApplyConfig(raw); err != nil {
		t.Fatalf("ApplyConfig failed with a valid bundle: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(etcDir, "config.yaml")); err != nil || string(data) != "node-name: test-node\n" {
		t.Fatalf("config.yaml not written as expected: %q (err %v)", string(data), err)
	}
	for _, name := range []string{"axonwall-openebs.yaml", "axonwall-workloads.yaml"} {
		if data, err := os.ReadFile(filepath.Join(manifestDir, name)); err != nil || string(data) != r2ValidK3sManifest {
			t.Fatalf("%s not written as expected: %q (err %v)", name, string(data), err)
		}
	}
	args, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(args), "reload-or-restart k3s") {
		t.Fatalf("systemctl reload-or-restart k3s was not invoked, log: %q (err %v)", string(args), err)
	}
}

// M15: a config write failure is returned, and k3s is not restarted
// on top of a half-written config.
func TestR2Batch6K3sApplyWriteFailureReturnsError(t *testing.T) {
	logPath := installFakeK3sPath(t, 0)
	etcDir, manifestDir, _, _ := redirectK3sPaths(t)
	mgr := NewK3sManager()
	// Block the config.yaml write by pre-creating it as a directory.
	if err := os.Mkdir(filepath.Join(etcDir, "config.yaml"), 0755); err != nil {
		t.Fatalf("failed to stage the blocking directory: %v", err)
	}

	raw := r2K3sBundleJSON(t, K3sRuntimeBundle{
		Enabled:               true,
		K3sConfigYaml:         "node-name: test-node\n",
		OpenEbsManifestYaml:   r2ValidK3sManifest,
		WorkloadsManifestYaml: r2ValidK3sManifest,
	})
	if err := mgr.ApplyConfig(raw); err == nil {
		t.Fatal("ApplyConfig succeeded when config.yaml could not be written; expected an error")
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatal("systemctl was invoked despite the config write failing")
	}
	if _, err := os.Stat(filepath.Join(manifestDir, "axonwall-openebs.yaml")); !os.IsNotExist(err) {
		t.Fatal("openebs manifest was written despite the config.yaml write failing")
	}
}

// M15: a failed k3s restart is returned instead of discarded while
// the bundle reports success.
func TestR2Batch6K3sApplyRestartFailureReturnsError(t *testing.T) {
	installFakeK3sPath(t, 1)
	etcDir, _, _, _ := redirectK3sPaths(t)
	mgr := NewK3sManager()

	raw := r2K3sBundleJSON(t, K3sRuntimeBundle{
		Enabled:       true,
		K3sConfigYaml: "node-name: test-node\n",
	})
	err := mgr.ApplyConfig(raw)
	if err == nil {
		t.Fatal("ApplyConfig succeeded when systemctl reload-or-restart failed; expected an error")
	}
	if !strings.Contains(err.Error(), "reload-or-restart") {
		t.Fatalf("error did not name the restart failure: %v", err)
	}
	// The config write itself still landed; only the restart failed.
	if _, err := os.Stat(filepath.Join(etcDir, "config.yaml")); err != nil {
		t.Fatalf("config.yaml was not written before the restart failure: %v", err)
	}
}

// M15: an enabled VOW bundle with an empty manifests field withdraws
// the deployment — the stale manifest is removed instead of staying
// live under k3s.
func TestR2Batch6K3sApplyVowEmptyManifestsRemovesStale(t *testing.T) {
	_, manifestDir, _, vowDir := redirectK3sPaths(t)
	mgr := NewK3sManager()
	stale := filepath.Join(manifestDir, "axonwall-vow.yaml")
	if err := os.WriteFile(stale, []byte("stale\n"), 0644); err != nil {
		t.Fatalf("failed to write stale VOW manifest: %v", err)
	}

	raw := r2VowBundleJSON(t, VowRuntimeBundle{
		Enabled:                  true,
		K3sDependencyMet:         true,
		CombinedK3sManifestsYaml: "",
		EnablerEnv:               "VOW_ENABLED=1\n",
	})
	if err := mgr.ApplyVowConfig(raw); err != nil {
		t.Fatalf("ApplyVowConfig failed with empty manifests: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale VOW manifest was not removed for an empty manifests field")
	}
	if data, err := os.ReadFile(filepath.Join(vowDir, ".env.enabler")); err != nil || string(data) != "VOW_ENABLED=1\n" {
		t.Fatalf(".env.enabler not written as expected: %q (err %v)", string(data), err)
	}
}

// M15: the VOW happy path still writes the manifest, env, and authz files.
func TestR2Batch6K3sApplyVowWritesManifest(t *testing.T) {
	_, manifestDir, _, vowDir := redirectK3sPaths(t)
	mgr := NewK3sManager()

	raw := r2VowBundleJSON(t, VowRuntimeBundle{
		Enabled:                  true,
		K3sDependencyMet:         true,
		CombinedK3sManifestsYaml: r2ValidK3sManifest,
		EnablerEnv:               "VOW_ENABLED=1\n",
		AuthzYaml:                "allow: true\n",
	})
	if err := mgr.ApplyVowConfig(raw); err != nil {
		t.Fatalf("ApplyVowConfig failed with a valid bundle: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(manifestDir, "axonwall-vow.yaml")); err != nil || string(data) != r2ValidK3sManifest {
		t.Fatalf("VOW manifest not written as expected: %q (err %v)", string(data), err)
	}
	if data, err := os.ReadFile(filepath.Join(vowDir, ".env.enabler")); err != nil || string(data) != "VOW_ENABLED=1\n" {
		t.Fatalf(".env.enabler not written as expected: %q (err %v)", string(data), err)
	}
	if data, err := os.ReadFile(filepath.Join(vowDir, "authz.yaml")); err != nil || string(data) != "allow: true\n" {
		t.Fatalf("authz.yaml not written as expected: %q (err %v)", string(data), err)
	}
}

// M15: a VOW write failure is returned, and the all-or-nothing write
// rolls back the files already staged in the same apply.
func TestR2Batch6K3sApplyVowWriteFailureReturnsError(t *testing.T) {
	_, manifestDir, _, vowDir := redirectK3sPaths(t)
	mgr := NewK3sManager()
	// Block the authz.yaml write by pre-creating it as a directory.
	if err := os.Mkdir(filepath.Join(vowDir, "authz.yaml"), 0755); err != nil {
		t.Fatalf("failed to stage the blocking directory: %v", err)
	}

	raw := r2VowBundleJSON(t, VowRuntimeBundle{
		Enabled:                  true,
		K3sDependencyMet:         true,
		CombinedK3sManifestsYaml: r2ValidK3sManifest,
		EnablerEnv:               "VOW_ENABLED=1\n",
		AuthzYaml:                "allow: true\n",
	})
	if err := mgr.ApplyVowConfig(raw); err == nil {
		t.Fatal("ApplyVowConfig succeeded when authz.yaml could not be written; expected an error")
	}
	if _, err := os.Stat(filepath.Join(vowDir, ".env.enabler")); !os.IsNotExist(err) {
		t.Fatal(".env.enabler was written despite the authz.yaml write failing")
	}
	if _, err := os.Stat(filepath.Join(manifestDir, "axonwall-vow.yaml")); !os.IsNotExist(err) {
		t.Fatal("VOW manifest was written despite the authz.yaml write failing")
	}
}
