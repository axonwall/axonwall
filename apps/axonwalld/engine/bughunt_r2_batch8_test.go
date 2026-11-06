package engine

import (
	"os"
	"strings"
	"testing"
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
