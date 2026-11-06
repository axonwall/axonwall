package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Round-2 batch 6 (daemon mediums) regression tests for A-M12
// (Vigilante ApplyConfig).

// redirectVigilantePaths points the Vigilante manifest and etc dirs at
// temp dirs and returns them.
func redirectVigilantePaths(t *testing.T) (manifestDir, etcDir string) {
	t.Helper()
	origM, origE := k3sServerManifestDir, vigilanteEtcDir
	manifestDir = t.TempDir()
	etcDir = t.TempDir()
	k3sServerManifestDir = manifestDir
	vigilanteEtcDir = etcDir
	t.Cleanup(func() {
		k3sServerManifestDir = origM
		vigilanteEtcDir = origE
	})
	return manifestDir, etcDir
}

const (
	r2ValidVigilanteManifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: vigilante\n"
	// ClusterRole is a denied manifest kind (see walkManifest).
	r2InvalidVigilanteManifest = "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: vigilante\n"
)

func r2VigilanteBundleJSON(t *testing.T, k3sEnabled bool, configYaml, ldapEnv, manifests string) []byte {
	t.Helper()
	raw, err := json.Marshal(VigilanteRuntimeBundle{
		Enabled:    true,
		K3sEnabled: k3sEnabled,
		CompiledBundle: &VigilanteCompiledBundle{
			K3sDependencyMet: true,
			ConfigYaml:       configYaml,
			LdapEnv:          ldapEnv,
			K3sManifests:     manifests,
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal vigilante bundle: %v", err)
	}
	return raw
}

// M12: an invalid manifest must fail BEFORE config.yaml / ldap.env are
// written, so a validation failure leaves the old config paired with
// the old manifest instead of new config paired with the stale one.
func TestR2Batch6VigilanteApplyValidatesManifestBeforeWriting(t *testing.T) {
	manifestDir, etcDir := redirectVigilantePaths(t)
	evidenceRoot := t.TempDir()
	vm := NewVigilanteManager(evidenceRoot)

	raw := r2VigilanteBundleJSON(t, true, "log: x\n", "FOO=bar\n", r2InvalidVigilanteManifest)
	if err := vm.ApplyConfig(raw); err == nil {
		t.Fatal("ApplyConfig succeeded with an invalid K3s manifest; expected a validation error")
	}
	if _, err := os.Stat(filepath.Join(evidenceRoot, "config.yaml")); !os.IsNotExist(err) {
		t.Fatal("config.yaml was written before manifest validation failed")
	}
	if _, err := os.Stat(filepath.Join(etcDir, "ldap.env")); !os.IsNotExist(err) {
		t.Fatal("ldap.env was written before manifest validation failed")
	}
	if _, err := os.Stat(filepath.Join(manifestDir, "axonwall-vigilante.yaml")); !os.IsNotExist(err) {
		t.Fatal("manifest was written despite failing validation")
	}
}

// M12: the happy path still writes all three files.
func TestR2Batch6VigilanteApplyWritesAllFiles(t *testing.T) {
	manifestDir, etcDir := redirectVigilantePaths(t)
	evidenceRoot := t.TempDir()
	vm := NewVigilanteManager(evidenceRoot)

	raw := r2VigilanteBundleJSON(t, true, "log: x\n", "FOO=bar\n", r2ValidVigilanteManifest)
	if err := vm.ApplyConfig(raw); err != nil {
		t.Fatalf("ApplyConfig failed with a valid bundle: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(evidenceRoot, "config.yaml")); err != nil || string(data) != "log: x\n" {
		t.Fatalf("config.yaml not written as expected: %q (err %v)", string(data), err)
	}
	if data, err := os.ReadFile(filepath.Join(etcDir, "ldap.env")); err != nil || string(data) != "FOO=bar\n" {
		t.Fatalf("ldap.env not written as expected: %q (err %v)", string(data), err)
	}
	if data, err := os.ReadFile(filepath.Join(manifestDir, "axonwall-vigilante.yaml")); err != nil || string(data) != r2ValidVigilanteManifest {
		t.Fatalf("manifest not written as expected: %q (err %v)", string(data), err)
	}
}

// M12: a write failure is returned (not swallowed as "Reconciled"),
// and the all-or-nothing write leaves none of the files behind.
func TestR2Batch6VigilanteApplyWriteFailureReturnsError(t *testing.T) {
	manifestDir, etcDir := redirectVigilantePaths(t)
	evidenceRoot := t.TempDir()
	vm := NewVigilanteManager(evidenceRoot)
	// Block the config.yaml write by pre-creating it as a directory.
	if err := os.Mkdir(filepath.Join(evidenceRoot, "config.yaml"), 0755); err != nil {
		t.Fatalf("failed to stage the blocking directory: %v", err)
	}

	raw := r2VigilanteBundleJSON(t, true, "log: x\n", "FOO=bar\n", r2ValidVigilanteManifest)
	if err := vm.ApplyConfig(raw); err == nil {
		t.Fatal("ApplyConfig succeeded when config.yaml could not be written; expected an error")
	}
	if _, err := os.Stat(filepath.Join(etcDir, "ldap.env")); !os.IsNotExist(err) {
		t.Fatal("ldap.env was written despite the config.yaml write failing")
	}
	if _, err := os.Stat(filepath.Join(manifestDir, "axonwall-vigilante.yaml")); !os.IsNotExist(err) {
		t.Fatal("manifest was written despite the config.yaml write failing")
	}
}

// M12: an empty manifests field withdraws the deployment — the stale
// manifest is removed while the new config still lands.
func TestR2Batch6VigilanteApplyEmptyManifestRemovesStale(t *testing.T) {
	manifestDir, etcDir := redirectVigilantePaths(t)
	evidenceRoot := t.TempDir()
	vm := NewVigilanteManager(evidenceRoot)
	stale := filepath.Join(manifestDir, "axonwall-vigilante.yaml")
	if err := os.WriteFile(stale, []byte("stale\n"), 0644); err != nil {
		t.Fatalf("failed to write stale manifest: %v", err)
	}

	raw := r2VigilanteBundleJSON(t, true, "log: x\n", "FOO=bar\n", "")
	if err := vm.ApplyConfig(raw); err != nil {
		t.Fatalf("ApplyConfig failed with empty manifests: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale manifest was not removed for an empty manifests field")
	}
	if data, err := os.ReadFile(filepath.Join(evidenceRoot, "config.yaml")); err != nil || string(data) != "log: x\n" {
		t.Fatalf("config.yaml not written as expected: %q (err %v)", string(data), err)
	}
	if data, err := os.ReadFile(filepath.Join(etcDir, "ldap.env")); err != nil || string(data) != "FOO=bar\n" {
		t.Fatalf("ldap.env not written as expected: %q (err %v)", string(data), err)
	}
}

// M12: a disabled bundle removes the stale manifest.
func TestR2Batch6VigilanteApplyDisabledRemovesStale(t *testing.T) {
	manifestDir, _ := redirectVigilantePaths(t)
	vm := NewVigilanteManager(t.TempDir())
	stale := filepath.Join(manifestDir, "axonwall-vigilante.yaml")
	if err := os.WriteFile(stale, []byte("stale\n"), 0644); err != nil {
		t.Fatalf("failed to write stale manifest: %v", err)
	}

	if err := vm.ApplyConfig([]byte(`{"enabled":false}`)); err != nil {
		t.Fatalf("ApplyConfig failed for a disabled bundle: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale manifest was not removed for a disabled bundle")
	}
}
