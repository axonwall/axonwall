package engine

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// D-04 Phase 3: the operator-facing sync trust status. Enrolled nodes
// report the pair's certificate fingerprints; unenrolled nodes report
// the fallback transports honestly.

func TestBuildSyncTrustStatusEnrolled(t *testing.T) {
	pki := makeTestPKI(t)
	caCert := loadCertFromPEMFile(t, pki.caCert)
	nodeCert := loadCertFromPEMFile(t, pki.nodeCert)

	cfg := SqliteSyncConfig{NodeRole: "backup", Transport: "mtls", RequireSignedPayloads: true}
	st := buildSyncTrustStatus(cfg, "", caCert, nodeCert)

	if !st.PKIEnrolled {
		t.Fatal("expected PKIEnrolled with both certificates present")
	}
	if st.TransportConfigured != "mtls" || st.RequireSignedPayloads != true {
		t.Fatalf("config fields not carried through: %+v", st)
	}
	// Fingerprint must be the colon-formatted SHA-256 of the DER bytes.
	sum := sha256.Sum256(nodeCert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	if want := strings.Join(parts, ":"); st.NodeCertFingerprint != want {
		t.Fatalf("node fingerprint mismatch:\n got %s\nwant %s", st.NodeCertFingerprint, want)
	}
	if st.CACertFingerprint == "" || st.CACertFingerprint == st.NodeCertFingerprint {
		t.Fatalf("CA fingerprint missing or equal to node fingerprint: %q", st.CACertFingerprint)
	}
	if st.NodeCertExpiresAt == "" || st.NodeCertSubject == "" {
		t.Fatal("expiry/subject not populated for an enrolled node")
	}
	// A backup has no serving transport; empty effective input falls back
	// to the configured transport.
	if st.TransportEffective != "mtls" {
		t.Fatalf("expected effective transport to fall back to configured 'mtls', got %q", st.TransportEffective)
	}
}

func TestBuildSyncTrustStatusUnenrolled(t *testing.T) {
	cfg := SqliteSyncConfig{NodeRole: "master", Transport: "mtls"}
	st := buildSyncTrustStatus(cfg, "token-http", nil, nil)
	if st.PKIEnrolled {
		t.Fatal("unenrolled node must not report PKIEnrolled")
	}
	if st.NodeCertFingerprint != "" || st.CACertFingerprint != "" {
		t.Fatal("unenrolled node must not report fingerprints")
	}
	// The P1 fallback state: mtls configured but token-http in effect.
	if st.TransportConfigured != "mtls" || st.TransportEffective != "token-http" {
		t.Fatalf("fallback transports misreported: %+v", st)
	}

	// Default config resolves to the product default, mtls, on both
	// fields (D-04 Phase 4); only an explicit value opts out.
	st2 := buildSyncTrustStatus(SqliteSyncConfig{}, "", nil, nil)
	if st2.TransportConfigured != "mtls" || st2.TransportEffective != "mtls" {
		t.Fatalf("empty config must resolve to the mtls default: %+v", st2)
	}
	st3 := buildSyncTrustStatus(SqliteSyncConfig{Transport: "token-http"}, "", nil, nil)
	if st3.TransportConfigured != "token-http" || st3.TransportEffective != "token-http" {
		t.Fatalf("explicit token-http opt-out must be honored: %+v", st3)
	}
}

func TestTrustStatusBackupEffectiveTransport(t *testing.T) {
	// No PKI material exists at the packaged paths in the test
	// environment, so even an mtls-configured backup reports the
	// token-http transport it can actually resolve (enrollment pending).
	m := NewSqliteSyncManager()
	m.cfg = SqliteSyncConfig{NodeRole: "backup", Transport: "mtls"}
	st := m.TrustStatus()
	if st.PKIEnrolled {
		t.Fatal("test environment unexpectedly has HA PKI material")
	}
	if st.TransportEffective != "token-http" {
		t.Fatalf("expected token-http effective transport pre-enrollment, got %q", st.TransportEffective)
	}
}
