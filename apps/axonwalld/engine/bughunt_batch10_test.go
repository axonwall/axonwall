package engine

// Round-2 bug-hunt fix batch 10 (daemon-low-2) regression tests:
// A-L21..A-L32. Tests that need live daemons, LDAP, or systemd (the
// full slapd bootstrap, the plugin LDAP integration against a real
// directory) are covered by the unit seams below, not by live
// services; see the batch report for the live-box items.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A-L21: a second Start() while the manager is running must be
// refused, not spawn a second monitorFlows that panics closing the
// same doneChan twice.
func TestBatch10EBPFDoubleStartRefused(t *testing.T) {
	mgr := NewEBPFManager()
	mgr.mu.Lock()
	mgr.running = true
	mgr.mu.Unlock()

	err := mgr.Start(nil)
	if err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("second Start() = %v, want \"already started\" error", err)
	}

	// Stop on a never-started manager must not panic or hang.
	mgr.mu.Lock()
	mgr.running = false
	mgr.mu.Unlock()
	mgr.Stop()
}

// A-L21: a failed Start() must clear the running flag so a later
// Start() can retry instead of being refused forever.
func TestBatch10EBPFStartFailureClearsRunning(t *testing.T) {
	mgr := NewEBPFManager()
	err := mgr.Start([]string{"lo"})
	if err == nil {
		// The sandbox can load eBPF after all: a second Start must
		// still be refused, and Stop must clean up.
		t.Cleanup(func() { mgr.Stop() })
		if err2 := mgr.Start([]string{"lo"}); err2 == nil || !strings.Contains(err2.Error(), "already started") {
			t.Fatalf("second Start() after successful Start = %v, want \"already started\" error", err2)
		}
		return
	}
	mgr.mu.Lock()
	running := mgr.running
	mgr.mu.Unlock()
	if running {
		t.Fatalf("failed Start() left running=true (err: %v)", err)
	}
}

// A-L22: a second concurrent StartVM for the same VM must be refused
// while the first start task is still running.
func TestBatch10VirtDoubleStartVMRefused(t *testing.T) {
	oldPath := VirtSpecsPath
	VirtSpecsPath = filepath.Join(t.TempDir(), "virt-specs.json")
	defer func() { VirtSpecsPath = oldPath }()

	mgr := NewVirtManager(NewTaskManager(), nil)

	// Deterministic pin: a flagged VMID is refused outright.
	mgr.startMu.Lock()
	if mgr.startingVMs == nil {
		mgr.startingVMs = make(map[int]bool)
	}
	mgr.startingVMs[101] = true
	mgr.startMu.Unlock()
	if _, err := mgr.StartVM(101, "root@axonwall"); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("StartVM on flagged VMID = %v, want \"already in progress\" error", err)
	}
	mgr.startMu.Lock()
	delete(mgr.startingVMs, 101)
	mgr.startMu.Unlock()

	// Live pin: two sequential starts; the first task is still
	// running (it has to fail through QEMU provisioning first), so
	// the second must hit the guard, not launch a second QEMU.
	// A-M26/C-D1 removed the fallback spec StartVM used to invent,
	// so the live pin registers a minimal spec first — the guard
	// under test is the double-start refusal, not the spec check.
	if err := mgr.RegisterVMSpec(CompiledVmSpec{VMID: 102, Name: "vm-102"}); err != nil {
		t.Fatalf("RegisterVMSpec(102) failed: %v", err)
	}
	upid, err := mgr.StartVM(102, "root@axonwall")
	if err != nil {
		t.Fatalf("first StartVM(102) failed: %v", err)
	}
	if upid == "" {
		t.Fatalf("first StartVM(102) returned an empty UPID")
	}
	if _, err := mgr.StartVM(102, "root@axonwall"); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("second StartVM(102) = %v, want \"already in progress\" error", err)
	}
}

// A-L23: the readiness poll must keep polling until the probe
// succeeds or the deadline passes.
func TestBatch10WaitForSlapdReady(t *testing.T) {
	orig := slapdReadyProbe
	defer func() { slapdReadyProbe = orig }()

	calls := 0
	slapdReadyProbe = func() bool {
		calls++
		return calls >= 3
	}
	if !waitForSlapdReady(5 * time.Second) {
		t.Fatalf("waitForSlapdReady did not return true once the probe succeeded")
	}
	if calls != 3 {
		t.Fatalf("expected the probe to run 3 times, ran %d times", calls)
	}

	slapdReadyProbe = func() bool { return false }
	start := time.Now()
	if waitForSlapdReady(400 * time.Millisecond) {
		t.Fatalf("waitForSlapdReady returned true with a probe that never succeeds")
	}
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Fatalf("waitForSlapdReady returned after %v, faster than its 400ms deadline", elapsed)
	}
}

// A-L23: the systemd gate must reflect the real PID 1.
func TestBatch10IsSystemdPID1MatchesProc(t *testing.T) {
	data, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		t.Skipf("no /proc/1/comm in this environment: %v", err)
	}
	want := strings.TrimSpace(string(data)) == "systemd"
	if got := isSystemdPID1(); got != want {
		t.Fatalf("isSystemdPID1() = %v, want %v (/proc/1/comm = %q)", got, want, strings.TrimSpace(string(data)))
	}
}

// A-L24: without hwmon sensors the telemetry must be empty, not
// hardcoded fake temperatures, fans, and optics.
func TestBatch10CollectTelemetryHasNoMockFallback(t *testing.T) {
	if entries, err := os.ReadDir("/sys/class/hwmon"); err == nil && len(entries) > 0 {
		t.Skip("host has real hwmon sensors; the mock-fallback path is not exercised here")
	}
	telem, err := NewHardwareManager().CollectTelemetry()
	if err != nil {
		t.Fatalf("CollectTelemetry failed: %v", err)
	}
	if len(telem.Temperatures) != 0 {
		t.Fatalf("expected no temperatures without hwmon, got %+v", telem.Temperatures)
	}
	if telem.CPUTempC != 0 {
		t.Fatalf("expected CPUTempC 0 without hwmon, got %v", telem.CPUTempC)
	}
	if len(telem.Fans) != 0 {
		t.Fatalf("expected no fans without hwmon, got %+v", telem.Fans)
	}
	if len(telem.Transceivers) != 0 {
		t.Fatalf("expected no transceivers without optics, got %+v", telem.Transceivers)
	}
}

// A-L25: unreadable posture inputs must be reported as unknown with
// empty values, not substituted with secure-looking defaults; and the
// audit no longer claims a hidden-module check ran (the
// HiddenModules field was removed).
func TestBatch10RootkitPostureUnknownNotFabricated(t *testing.T) {
	posture := InspectKernelPosture()
	checkUnknown := func(path, field string, get func() string) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if got := get(); got != "" {
				t.Errorf("expected empty %s when %s is unreadable, got %q", field, path, got)
			}
			found := false
			for _, f := range posture.UnknownFields {
				if f == field {
					found = true
				}
			}
			if !found {
				t.Errorf("expected %q in UnknownFields %v", field, posture.UnknownFields)
			}
		}
	}
	checkUnknown("/sys/kernel/security/lsm", "kernel.security.lsm", func() string {
		return strings.Join(posture.ActiveLsms, ",")
	})
	checkUnknown("/proc/sys/kernel/unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled", func() string {
		return posture.UnprivilegedBpfDisabled
	})
	checkUnknown("/proc/sys/net/core/bpf_jit_harden", "net.core.bpf_jit_harden", func() string {
		return posture.BpfJitHarden
	})

	audit := RunHostRootkitAudit()
	if audit.Timestamp == "" {
		t.Fatalf("expected a non-empty audit timestamp")
	}
}

// A-L26: an installed-but-never-initialised etckeeper repo must not
// report Clean=true.
func TestBatch10EtckeeperUninitializedIsNotClean(t *testing.T) {
	mgr := NewEtckeeperManager(t.TempDir())
	mgr.execCmd = func(name string, args ...string) *exec.Cmd {
		if name == "which" {
			return exec.Command("true")
		}
		return exec.Command("true")
	}
	status := mgr.GetStatus()
	if !status.Installed {
		t.Fatalf("expected Installed=true with a mocked etckeeper binary")
	}
	if status.Initialized {
		t.Fatalf("expected Initialized=false with no .git in the tracked dir")
	}
	if status.Clean {
		t.Fatalf("uninitialized etckeeper repo reported Clean=true")
	}
}

// A-L26: a failed git status must not report Clean=true either.
func TestBatch10EtckeeperFailedGitStatusIsNotClean(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	mgr := NewEtckeeperManager(dir)
	mgr.execCmd = func(name string, args ...string) *exec.Cmd {
		if name == "which" {
			return exec.Command("true")
		}
		if name == "git" {
			return exec.Command("false")
		}
		return exec.Command("true")
	}
	status := mgr.GetStatus()
	if !status.Initialized {
		t.Fatalf("expected Initialized=true with a .git dir present")
	}
	if status.Clean {
		t.Fatalf("failed git status reported Clean=true")
	}
}

// A-L27: both state.json copies must be merged; a peer IP that only
// exists in the second copy must still be protected.
func TestBatch10DiscoverProtectedPostureMergesBothStateFiles(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "state1.json")
	second := filepath.Join(dir, "state2.json")
	if err := os.WriteFile(first, []byte(`{"ha": {"peerIp": "10.0.0.11"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte(`{"ha": {"peerIp": "10.0.0.12"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	old := protectedPostureStatePaths
	protectedPostureStatePaths = []string{first, second}
	defer func() { protectedPostureStatePaths = old }()

	posture := DiscoverProtectedPosture()
	has := func(ip string) bool {
		for _, g := range posture.GatewayAndHaIPs {
			if g == ip {
				return true
			}
		}
		return false
	}
	if !has("10.0.0.11") || !has("10.0.0.12") {
		t.Fatalf("expected both HA peer IPs protected, got %v", posture.GatewayAndHaIPs)
	}
}

// A-L28: a port with trailing junk ("80abc") must be rejected, not
// silently parsed as 80.
func TestBatch10ValidateRedirectDestinationRejectsTrailingJunkPort(t *testing.T) {
	for _, dest := range []string{"10.0.0.5:8080x", "10.0.0.5:80abc"} {
		if _, _, _, _, err := ValidateRedirectDestination(dest); err == nil {
			t.Fatalf("ValidateRedirectDestination(%q) succeeded, want an error", dest)
		}
	}
	host, port, _, norm, err := ValidateRedirectDestination("10.0.0.5:8080")
	if err != nil {
		t.Fatalf("ValidateRedirectDestination(10.0.0.5:8080) failed: %v", err)
	}
	if host != "10.0.0.5" || port != 8080 || norm != "10.0.0.5:8080" {
		t.Fatalf("ValidateRedirectDestination(10.0.0.5:8080) = (%q, %d, %q), want (10.0.0.5, 8080, 10.0.0.5:8080)", host, port, norm)
	}
}

// A-L29: an unreadable PCI sysfs tree must be an error, not an empty
// device list.
func TestBatch10DiscoverPciDevicesErrorsWhenSysfsUnreadable(t *testing.T) {
	mgr := &VFIOManager{sysfsRoot: filepath.Join(t.TempDir(), "nosuchsys")}
	if _, err := mgr.DiscoverPciDevices(); err == nil {
		t.Fatalf("DiscoverPciDevices with unreadable sysfs returned nil error")
	}
}

// A-L29: UnbindVfio must report an error when the device is still
// bound to vfio-pci after the unbind writes.
func TestBatch10UnbindVfioReportsStillBound(t *testing.T) {
	root := t.TempDir()
	bdf := "0000:00:01.0"
	devDir := filepath.Join(root, "bus", "pci", "devices", bdf)
	if err := os.MkdirAll(devDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bus", "pci", "drivers", "vfio-pci"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(root, "bus", "pci", "drivers", "vfio-pci", "unbind"),
		filepath.Join(root, "bus", "pci", "rescan"),
		filepath.Join(devDir, "driver_override"),
	} {
		if err := os.WriteFile(p, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
	}
	// The writes succeed but the driver symlink never moves: the
	// device is still bound, so UnbindVfio must fail.
	if err := os.Symlink(filepath.Join(root, "bus", "pci", "drivers", "vfio-pci"), filepath.Join(devDir, "driver")); err != nil {
		t.Fatal(err)
	}
	mgr := &VFIOManager{sysfsRoot: root}
	if err := mgr.UnbindVfio(bdf); err == nil {
		t.Fatalf("UnbindVfio returned nil while the device is still bound to vfio-pci")
	}
}

// A-L29: a device bound to another driver is already released.
func TestBatch10UnbindVfioAlreadyUnboundSucceeds(t *testing.T) {
	root := t.TempDir()
	bdf := "0000:00:01.0"
	devDir := filepath.Join(root, "bus", "pci", "devices", bdf)
	if err := os.MkdirAll(devDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bus", "pci", "drivers", "vfio-pci"), 0755); err != nil {
		t.Fatal(err)
	}
	otherDriver := filepath.Join(root, "bus", "pci", "drivers", "virtio-pci")
	if err := os.MkdirAll(otherDriver, 0755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(root, "bus", "pci", "drivers", "vfio-pci", "unbind"),
		filepath.Join(root, "bus", "pci", "rescan"),
		filepath.Join(devDir, "driver_override"),
	} {
		if err := os.WriteFile(p, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(otherDriver, filepath.Join(devDir, "driver")); err != nil {
		t.Fatal(err)
	}
	mgr := &VFIOManager{sysfsRoot: root}
	if err := mgr.UnbindVfio(bdf); err != nil {
		t.Fatalf("UnbindVfio on a device bound to another driver failed: %v", err)
	}
}

// A-L30: a failed sshd reload after writing the policy must be an
// error, not a silent success.
func TestBatch10SyncRootSshPolicyReloadFailureIsError(t *testing.T) {
	dir := t.TempDir()
	old := axonwallSshdConfPath
	axonwallSshdConfPath = filepath.Join(dir, "axonwall.conf")
	defer func() { axonwallSshdConfPath = old }()

	dm := &DirectoryManager{policy: DefaultPasswordPolicyConfig()}
	if err := dm.SyncRootSshPolicy(); err == nil {
		t.Fatalf("SyncRootSshPolicy returned nil even though no sshd reload can succeed here")
	}
	if _, err := os.Stat(axonwallSshdConfPath); err != nil {
		t.Fatalf("expected the config to have been written before the reload failed: %v", err)
	}
	// Second call: content is unchanged, so no write and no reload.
	if err := dm.SyncRootSshPolicy(); err != nil {
		t.Fatalf("unchanged config should not reload: %v", err)
	}
}

// A-L30: a failed config write must be an error too.
func TestBatch10SyncRootSshPolicyWriteFailureIsError(t *testing.T) {
	old := axonwallSshdConfPath
	axonwallSshdConfPath = "/proc/definitely-not-here/axonwall.conf"
	defer func() { axonwallSshdConfPath = old }()

	dm := &DirectoryManager{policy: DefaultPasswordPolicyConfig()}
	if err := dm.SyncRootSshPolicy(); err == nil {
		t.Fatalf("SyncRootSshPolicy returned nil for an unwritable config path")
	}
}

// A-L31: a public key whose secret key is missing must not trigger a
// silent re-key; only an explicit force may rotate.
func TestBatch10GenerateRosenpassKeypairRefusesRekeyWhenSecretMissing(t *testing.T) {
	dir := t.TempDir()
	sha1, _, err := GenerateRosenpassKeypair(dir, false)
	if err != nil {
		t.Fatalf("GenerateRosenpassKeypair failed: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "pq.sk")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenerateRosenpassKeypair(dir, false); err == nil {
		t.Fatalf("GenerateRosenpassKeypair re-keyed silently with pq.pk present but pq.sk missing")
	}
	sha2, _, err := GenerateRosenpassKeypair(dir, true)
	if err != nil {
		t.Fatalf("force re-key failed: %v", err)
	}
	if sha2 == sha1 {
		t.Fatalf("force re-key produced an identical key")
	}
}

// A-L32: the plugin LDAP integration must fail when its binding
// files cannot be written, not report success.
func TestBatch10EnsurePluginLDAPIntegrationBindingWriteFailure(t *testing.T) {
	oldClients, oldSecrets := ldapPluginClientsDir, ldapPluginSecretsDir
	ldapPluginClientsDir = "/proc/definitely-not-here/ldap-plugins"
	ldapPluginSecretsDir = filepath.Join(t.TempDir(), "secrets")
	defer func() { ldapPluginClientsDir, ldapPluginSecretsDir = oldClients, oldSecrets }()

	dm := &DirectoryManager{baseDN: "dc=axonwall,dc=local", policy: DefaultPasswordPolicyConfig()}
	if _, err := dm.EnsurePluginLDAPIntegration("test-plugin", PluginLDAPSpec{ServiceAccountCN: "svc-test-plugin"}); err == nil {
		t.Fatalf("EnsurePluginLDAPIntegration returned nil even though the binding files cannot be written")
	}
}

// A-L32: with writable dirs the binding files must actually exist.
func TestBatch10EnsurePluginLDAPIntegrationWritesBinding(t *testing.T) {
	dir := t.TempDir()
	oldClients, oldSecrets := ldapPluginClientsDir, ldapPluginSecretsDir
	ldapPluginClientsDir = filepath.Join(dir, "clients")
	ldapPluginSecretsDir = filepath.Join(dir, "secrets")
	defer func() { ldapPluginClientsDir, ldapPluginSecretsDir = oldClients, oldSecrets }()

	dm := &DirectoryManager{baseDN: "dc=axonwall,dc=local", policy: DefaultPasswordPolicyConfig()}
	binding, err := dm.EnsurePluginLDAPIntegration("test-plugin", PluginLDAPSpec{ServiceAccountCN: "svc-test-plugin"})
	if err != nil {
		t.Fatalf("EnsurePluginLDAPIntegration failed: %v", err)
	}
	if binding == nil || binding.BindDN == "" {
		t.Fatalf("expected a binding with a BindDN, got %+v", binding)
	}
	for _, name := range []string{"test-plugin.json", "test-plugin.env"} {
		if _, err := os.Stat(filepath.Join(ldapPluginClientsDir, name)); err != nil {
			t.Fatalf("expected binding file %s to exist: %v", name, err)
		}
	}
}

// A-L32: a failed password rotation on an existing service account
// must be an error, not a discarded ldapmodify.
func TestBatch10EnsurePluginLDAPIntegrationRotationFailure(t *testing.T) {
	binDir := t.TempDir()
	ldapadd := "#!/bin/sh\necho \"Already exists\"\nexit 1\n"
	ldapmodify := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "ldapadd"), []byte(ldapadd), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "ldapmodify"), []byte(ldapmodify), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	dir := t.TempDir()
	oldClients, oldSecrets := ldapPluginClientsDir, ldapPluginSecretsDir
	ldapPluginClientsDir = filepath.Join(dir, "clients")
	ldapPluginSecretsDir = filepath.Join(dir, "secrets")
	defer func() { ldapPluginClientsDir, ldapPluginSecretsDir = oldClients, oldSecrets }()

	dm := &DirectoryManager{baseDN: "dc=axonwall,dc=local", policy: DefaultPasswordPolicyConfig()}
	_, err := dm.EnsurePluginLDAPIntegration("test-plugin", PluginLDAPSpec{ServiceAccountCN: "svc-test-plugin"})
	if err == nil || !strings.Contains(err.Error(), "rotate") {
		t.Fatalf("expected a rotation error, got: %v", err)
	}
}
