package engine

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// D-04 Phase 2: /db and /state payloads are signed with the HA node key;
// the poller verifies before applying. These tests pin the round trip,
// the tamper and foreign-key negative controls, the handler header, and
// the requireSignedPayloads gate semantics.

func loadKeyFromPEMFile(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func loadCertFromPEMFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// withTestPKISeams points the package signing seams at a temp PKI for the
// duration of one test.
func withTestPKISeams(t *testing.T, p testPKI) {
	t.Helper()
	key := loadKeyFromPEMFile(t, p.nodeKey)
	cert := loadCertFromPEMFile(t, p.nodeCert)
	oldSign, oldVerify := haSignPayloadDigest, haVerifyPayloadSignature
	haSignPayloadDigest = func(digest []byte) (string, error) { return signPayloadDigest(key, digest) }
	haVerifyPayloadSignature = func(digest []byte, sig string) bool {
		return verifyPayloadSignatureWithCert(cert, digest, sig)
	}
	t.Cleanup(func() { haSignPayloadDigest, haVerifyPayloadSignature = oldSign, oldVerify })
}

func TestPayloadSignatureRoundTripAndTamper(t *testing.T) {
	pki := makeTestPKI(t)
	key := loadKeyFromPEMFile(t, pki.nodeKey)
	cert := loadCertFromPEMFile(t, pki.nodeCert)

	digest := sha256.Sum256([]byte("peer state"))
	sig, err := signPayloadDigest(key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !verifyPayloadSignatureWithCert(cert, digest[:], sig) {
		t.Fatal("valid signature did not verify")
	}

	// Tampered payload: same signature, different digest -> reject.
	other := sha256.Sum256([]byte("attacker state"))
	if verifyPayloadSignatureWithCert(cert, other[:], sig) {
		t.Fatal("signature verified against a different payload digest")
	}

	// Foreign key: signed by a different pair's key -> reject.
	foreign := makeTestPKI(t)
	foreignKey := loadKeyFromPEMFile(t, foreign.nodeKey)
	foreignSig, err := signPayloadDigest(foreignKey, digest[:])
	if err != nil {
		t.Fatalf("foreign sign: %v", err)
	}
	if verifyPayloadSignatureWithCert(cert, digest[:], foreignSig) {
		t.Fatal("foreign-key signature verified against the pair certificate")
	}

	// Garbage signature encoding -> reject, not panic.
	if verifyPayloadSignatureWithCert(cert, digest[:], "!!!not-base64!!!") {
		t.Fatal("garbage signature verified")
	}
}

func TestDownloadDbServesPayloadSignature(t *testing.T) {
	pki := makeTestPKI(t)
	withTestPKISeams(t, pki)

	dbFile := filepath.Join(t.TempDir(), "headscale.sqlite")
	if err := os.WriteFile(dbFile, []byte("fake-db-contents"), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewSqliteSyncManager()
	m.cfg = SqliteSyncConfig{Enabled: true, NodeRole: "master", AuthToken: "tok", Databases: []string{dbFile}}

	req := httptest.NewRequest("GET", "/api/v1/sync/db?path="+dbFile, nil)
	req.Header.Set("X-Axonwall-Sync-Token", "tok")
	rec := httptest.NewRecorder()
	m.handleDownloadDb(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	sig := rec.Header().Get("X-Axonwall-Payload-Signature")
	if sig == "" {
		t.Fatal("signed pair served no X-Axonwall-Payload-Signature header")
	}
	// The signature must verify over the declared checksum digest.
	sum := sha256.Sum256(rec.Body.Bytes())
	if got := rec.Header().Get("X-Checksum-SHA256"); got == "" {
		t.Fatal("missing checksum header")
	}
	cert := loadCertFromPEMFile(t, pki.nodeCert)
	if !verifyPayloadSignatureWithCert(cert, sum[:], sig) {
		t.Fatal("served signature does not verify over the payload digest")
	}
}

func TestVerifyPeerPayloadGate(t *testing.T) {
	pki := makeTestPKI(t)
	withTestPKISeams(t, pki)
	digest := sha256.Sum256([]byte("payload"))

	newMgr := func(require bool) *SqliteSyncManager {
		m := NewSqliteSyncManager()
		m.cfg = SqliteSyncConfig{RequireSignedPayloads: require}
		return m
	}

	// Unsigned + gate off: allowed (migration default).
	if err := newMgr(false).verifyPeerPayload("state", digest[:], ""); err != nil {
		t.Fatalf("unsigned payload should be allowed with the gate off: %v", err)
	}
	// Unsigned + gate on: refused.
	if err := newMgr(true).verifyPeerPayload("state", digest[:], ""); err == nil {
		t.Fatal("unsigned payload must be refused with requireSignedPayloads on")
	}
	// Invalid signature: refused regardless of the gate.
	if err := newMgr(false).verifyPeerPayload("state", digest[:], "AAAA"); err == nil {
		t.Fatal("invalid signature must be refused even with the gate off")
	}
	// Valid signature: allowed with the gate on.
	key := loadKeyFromPEMFile(t, pki.nodeKey)
	sig, err := signPayloadDigest(key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := newMgr(true).verifyPeerPayload("state", digest[:], sig); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
}
