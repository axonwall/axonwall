package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Round-2 batch 8 (daemon-med-3) regression tests.

// A-M31: BuildSSSDConfig emitted "ldap_tls_cacert = <HAPKICACertPath>"
// whenever a peer URI was set, even when that file does not exist yet —
// with ldap_tls_reqcert=demand, sssd then failed to start. The config
// must never point at a CA file that does not exist.
func TestBatch8SSSDConfigNoMissingCACert(t *testing.T) {
	_, caErr := os.Stat("/etc/axonwall/pki/ca.crt")
	_, haErr := os.Stat(HAPKICACertPath)
	if caErr == nil || haErr == nil {
		t.Skip("a CA cert exists on this host; the missing-CA case does not apply")
	}
	cfg := BuildSSSDConfig("dc=axonwall,dc=local", "ldap://10.0.0.2:389")
	if strings.Contains(cfg, HAPKICACertPath) {
		t.Fatalf("SSSD config points at a CA file that does not exist:\n%s", cfg)
	}
	if strings.Contains(cfg, "ldap_tls_reqcert = demand") {
		t.Fatalf("SSSD config demands a cert with no CA file present:\n%s", cfg)
	}
	if !strings.Contains(cfg, "ldap_tls_reqcert = never") {
		t.Fatalf("SSSD config should fall back to reqcert=never with no CA file:\n%s", cfg)
	}
}

// A-M32: a break-glass admin seeding failure must be recorded and
// surfaced in GetStatus instead of being silently skipped.
func TestBatch8AdminSeedErrorSurfaced(t *testing.T) {
	// A zero manager would nil-deref in GetStatus (it reads user
	// counts via localUsers); a manager with a real UserManager is
	// enough — no LDAP is touched when slapd is down.
	d := &DirectoryManager{localUsers: NewUserManager(nil)}
	if got := d.GetStatus().AdminSeedError; got != "" {
		t.Fatalf("fresh manager should have no admin seed error, got %q", got)
	}
	d.setAdminSeedError("break-glass admin seeding failed: boom")
	if got := d.GetStatus().AdminSeedError; got != "break-glass admin seeding failed: boom" {
		t.Fatalf("GetStatus did not surface the seed error, got %q", got)
	}
	d.clearAdminSeedError()
	if got := d.GetStatus().AdminSeedError; got != "" {
		t.Fatalf("seed error should clear after success, got %q", got)
	}
}

// A-M33: EnablePlugin must surface a systemd unit failure instead of
// reporting success, and must not leave the plugin recorded as enabled.
func TestBatch8PluginEnableSurfacesSystemdFailure(t *testing.T) {
	if !systemctlAvailable() {
		t.Skip("no systemctl on this host; the systemd failure path does not apply")
	}
	pm := NewPluginManager(t.TempDir())
	resp := pm.EnablePlugin("haproxy")
	if resp.Success {
		t.Fatalf("EnablePlugin(haproxy) should fail when its unit cannot be started, got success: %s", resp.Message)
	}
	for _, p := range pm.ListPlugins() {
		if p.ID == "haproxy" && p.Enabled {
			t.Fatalf("haproxy must not be reported enabled after a failed enable")
		}
	}
}

// A-M33: DisablePlugin must record the plugin disabled once its units
// are actually stopped (no unit is running for haproxy here, so the
// disable must succeed and be recorded).
func TestBatch8PluginDisableRecorded(t *testing.T) {
	pm := NewPluginManager(t.TempDir())
	resp := pm.DisablePlugin("haproxy")
	if !resp.Success {
		t.Fatalf("DisablePlugin(haproxy) should succeed with no unit running, got: %s", resp.Message)
	}
	for _, p := range pm.ListPlugins() {
		if p.ID == "haproxy" && p.Enabled {
			t.Fatalf("haproxy must be reported disabled after DisablePlugin")
		}
	}
}

// A-M33: the rosenpass unit verification must fail when the unit file
// does not exist (instead of Reconfigure claiming "verified").
func TestBatch8VerifyRosenpassUnitMissing(t *testing.T) {
	if !systemctlAvailable() {
		t.Skip("no systemctl on this host; unit verification is skipped there")
	}
	if err := verifyRosenpassUnit(); err == nil {
		t.Fatalf("verifyRosenpassUnit should fail with no unit file present")
	}
}

// A-M34: HA PKI imports must reject empty/unparseable PEM and
// mismatched keys instead of writing them to disk and reporting success.
// These tests assert rejection only: validation runs before any write,
// so they have no filesystem side effects on this shared box.
func batch8TestSelfSignedCert(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "batch8-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating test certificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestBatch8HAPKIBundleValidation(t *testing.T) {
	caCert, caKey := batch8TestSelfSignedCert(t)
	nodeCert, _ := batch8TestSelfSignedCert(t)
	_, otherKey := batch8TestSelfSignedCert(t)

	// The pure validators accept good material and a matching pair.
	if _, err := parsePEMCertificate("CA certificate", caCert); err != nil {
		t.Fatalf("parsePEMCertificate(valid cert) failed: %v", err)
	}
	if err := validatePEMCertKeyPair("CA certificate", caCert, "CA key", caKey); err != nil {
		t.Fatalf("validatePEMCertKeyPair(matching pair) failed: %v", err)
	}
	if err := validatePEMCertKeyPair("node certificate", nodeCert, "node key", otherKey); err == nil {
		t.Fatalf("validatePEMCertKeyPair must reject a key that does not match the cert")
	}

	// ImportHAPKIBundle must reject empty / garbage / mismatched input.
	for _, tc := range []struct {
		name   string
		bundle HAPKIBundle
	}{
		{"empty bundle", HAPKIBundle{}},
		{"empty CA", HAPKIBundle{CACertPEM: "", NodeCertPEM: nodeCert}},
		{"garbage CA", HAPKIBundle{CACertPEM: "not pem at all", NodeCertPEM: nodeCert}},
		{"garbage node cert", HAPKIBundle{CACertPEM: caCert, NodeCertPEM: "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----"}},
		{"mismatched node key", HAPKIBundle{CACertPEM: caCert, NodeCertPEM: nodeCert, NodeKeyPEM: otherKey}},
		{"mismatched CA key", HAPKIBundle{CACertPEM: caCert, CAKeyPEM: otherKey, NodeCertPEM: nodeCert}},
	} {
		if err := ImportHAPKIBundle(tc.bundle); err == nil {
			t.Fatalf("ImportHAPKIBundle(%s) should fail", tc.name)
		}
	}

	// InstallHAPKICSRResponse must reject garbage the same way (the
	// old code only checked non-emptiness and wrote it to disk).
	for _, tc := range []struct {
		name string
		resp *HAPKICSRResponse
	}{
		{"garbage CA", &HAPKICSRResponse{CACertPEM: "not pem", SignedCertPEM: nodeCert}},
		{"garbage signed cert", &HAPKICSRResponse{CACertPEM: caCert, SignedCertPEM: "not pem"}},
		{"garbage peer cert", &HAPKICSRResponse{CACertPEM: caCert, SignedCertPEM: nodeCert, PeerSignerCertPEM: "not pem"}},
	} {
		if err := InstallHAPKICSRResponse(tc.resp); err == nil {
			t.Fatalf("InstallHAPKICSRResponse(%s) should fail", tc.name)
		}
	}
}

// A-M43: process liveness must distinguish a living process from a
// dead (or zombie) one — Signal(0) alone also succeeds for zombies.
func TestBatch8ProcessAlive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatalf("processAlive(self) should be true")
	}
	if processAlive(1 << 22) {
		t.Fatalf("processAlive on a nonexistent pid should be false")
	}
	// A reaped child is dead.
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn test child: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("waiting for test child: %v", err)
	}
	if processAlive(pid) {
		t.Fatalf("processAlive(reaped child %d) should be false", pid)
	}
}

// A-M43: with no caddy running and no caddy binary installed, a reload
// must report failure instead of claiming the proxy started.
func TestBatch8ReloadCaddyFailsWithoutBinary(t *testing.T) {
	if _, err := exec.LookPath("caddy"); err == nil {
		t.Skip("caddy is installed on this host; the no-binary case does not apply")
	}
	if pid, err := readCaddyPidFile(); err == nil && processAlive(pid) {
		t.Skip("a caddy from another lifetime is recorded alive; skipping")
	}
	m := NewIAPManager()
	if err := m.ReloadCaddy(filepath.Join(t.TempDir(), "Caddyfile")); err == nil {
		t.Fatalf("ReloadCaddy should fail when caddy cannot be started")
	}
	// Stop on a fresh manager must be a harmless no-op.
	m.Stop()
}

// A-M43: a fresh manager must report no caddy alive (no handle, and no
// live pid in the pidfile).
func TestBatch8CaddyAliveFresh(t *testing.T) {
	if pid, err := readCaddyPidFile(); err == nil && processAlive(pid) {
		t.Skip("a caddy from another lifetime is recorded alive; skipping")
	}
	m := NewIAPManager()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.caddyAliveLocked() {
		t.Fatalf("fresh IAPManager should report no caddy alive")
	}
}

// A-M44: provisioning the vault on a box without zfs must fail instead
// of reporting "provisioned" while evidence lands on the root
// filesystem. (Skipped where zfs exists; there the dataset path is
// exercised by the live box, not this sandbox.)
func TestBatch8ProvisionEvidenceVaultRequiresZFS(t *testing.T) {
	if _, err := exec.LookPath("zfs"); err == nil {
		t.Skip("zfs is installed on this host; the no-zfs case does not apply")
	}
	root := t.TempDir()
	vm := NewVigilanteManager(root)
	if err := vm.ProvisionEvidenceVault("tank", "vigilante-evidence"); err == nil {
		t.Fatalf("ProvisionEvidenceVault should fail with no zfs dataset present")
	}
	// The old fallback created the subdirs under the evidence root
	// on /; nothing must be created now.
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatalf("no vault subdirs must be created when provisioning fails, found %v", entries)
	}
}

// A-M44: isMountpoint must distinguish a real mount from a directory
// that merely exists.
func TestBatch8IsMountpoint(t *testing.T) {
	if !isMountpoint("/") {
		t.Fatalf("isMountpoint(/) should be true")
	}
	if isMountpoint(t.TempDir()) {
		t.Fatalf("isMountpoint(temp dir) should be false")
	}
	if got := unescapeMountField(`/mnt/my\040data`); got != "/mnt/my data" {
		t.Fatalf("unescapeMountField = %q, want %q", got, "/mnt/my data")
	}
}
