package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// D-04 Phase 1: the HA sync endpoints served over the HA PKI mutual-TLS
// transport. A client must present a certificate chaining to the shared HA
// CA AND the shared sync token; plain HTTP and foreign-CA clients are
// rejected at the handshake, before any handler runs.

type testPKI struct {
	caCert, caKey, nodeCert, nodeKey string
}

func makeTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	p := testPKI{
		caCert:   filepath.Join(dir, "ca.crt"),
		caKey:    filepath.Join(dir, "ca.key"),
		nodeCert: filepath.Join(dir, "node.crt"),
		nodeKey:  filepath.Join(dir, "node.key"),
	}
	if err := EnsureHAPKICertsInDir(dir, p.caCert, p.caKey, p.nodeCert, p.nodeKey, "testnode", "127.0.0.1", "127.0.0.1"); err != nil {
		t.Fatalf("EnsureHAPKICertsInDir: %v", err)
	}
	return p
}

func (p testPKI) tlsConfig(t *testing.T) *tls.Config {
	t.Helper()
	cfg, err := LoadHAPKITLSConfigFromPaths(p.caCert, p.nodeCert, p.nodeKey)
	if err != nil {
		t.Fatalf("LoadHAPKITLSConfigFromPaths: %v", err)
	}
	return cfg
}

func (p testPKI) client(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig(t)},
	}
}

func newMTLSManager() *SqliteSyncManager {
	m := NewSqliteSyncManager()
	m.cfg = SqliteSyncConfig{
		Enabled:    true,
		NodeRole:   "master",
		Transport:  "mtls",
		AuthToken:  "sync-secret",
		Databases:  []string{},
		ListenPort: 9876,
	}
	m.effectiveTransport = "mtls"
	return m
}

func TestSqliteSyncMTLSRoundTrip(t *testing.T) {
	pki := makeTestPKI(t)
	mgr := newMTLSManager()

	srv := httptest.NewUnstartedServer(mgr.syncMux())
	srv.TLS = pki.tlsConfig(t)
	srv.StartTLS()
	defer srv.Close()

	// Valid node certificate + token: 200, and the status reports the
	// effective transport.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/sync/status", nil)
	req.Header.Set("X-Axonwall-Sync-Token", "sync-secret")
	resp, err := pki.client(t).Do(req)
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var status SyncStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Transport != "mtls" {
		t.Fatalf("expected transport 'mtls' in status, got %q", status.Transport)
	}

	// Valid certificate, NO token: the token check still applies over
	// mTLS (defense in depth) -> 401.
	req2, _ := http.NewRequest("GET", srv.URL+"/api/v1/sync/status", nil)
	resp2, err := pki.client(t).Do(req2)
	if err != nil {
		t.Fatalf("mTLS request without token errored at transport: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp2.StatusCode)
	}
}

func TestSqliteSyncMTLSRejectsPlainHTTPAndForeignCA(t *testing.T) {
	pki := makeTestPKI(t)
	mgr := newMTLSManager()

	srv := httptest.NewUnstartedServer(mgr.syncMux())
	srv.TLS = pki.tlsConfig(t)
	srv.StartTLS()
	defer srv.Close()

	// Plain HTTP against the TLS listener serves nothing: Go's server
	// answers a bare 400 ("client sent an HTTP request to an HTTPS
	// server") without running any handler, so the property to pin is
	// that no sync response is ever returned.
	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Get(strings.Replace(srv.URL, "https://", "http://", 1) + "/api/v1/sync/status")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("plain HTTP request was served by the mTLS listener")
		}
	}

	// A node certificate from a DIFFERENT CA fails the handshake.
	foreign := makeTestPKI(t)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/sync/status", nil)
	req.Header.Set("X-Axonwall-Sync-Token", "sync-secret")
	if _, err := foreign.client(t).Do(req); err == nil {
		t.Fatal("foreign-CA client unexpectedly completed the mTLS handshake")
	}
}

func TestPeerClientFallsBackToHTTPWithoutPKI(t *testing.T) {
	// A node whose HA PKI was never enrolled has no certificate to
	// present; the poller must fall back to the token-http transport so
	// enrollment can still happen. (The packaged PKI paths do not exist
	// in the test environment.)
	for _, transport := range []string{"mtls", "token-http", ""} {
		m := NewSqliteSyncManager()
		m.cfg = SqliteSyncConfig{Transport: transport}
		_, scheme := m.peerClient(5 * time.Second)
		if scheme != "http" {
			t.Fatalf("transport %q: expected http fallback without PKI, got %q", transport, scheme)
		}
	}
	if !newMTLSManager().mtlsRequested() {
		t.Fatal("mtlsRequested should be true for transport 'mtls'")
	}
	// D-04 Phase 4: the empty value resolves to the mtls default; only
	// an explicit "token-http" opts out to the legacy transport.
	m := NewSqliteSyncManager()
	m.cfg = SqliteSyncConfig{}
	if !m.mtlsRequested() {
		t.Fatal("mtlsRequested should be true for the empty (default) transport")
	}
	m.cfg = SqliteSyncConfig{Transport: "token-http"}
	if m.mtlsRequested() {
		t.Fatal("mtlsRequested should be false for explicit transport 'token-http'")
	}
}

// R4-A-H2: HA PKI enrollment must use verified HTTPS against the peer
// CA and never downgrade to plaintext HTTP or skip verification. The
// old code tried HTTPS with InsecureSkipVerify and fell back to plain
// HTTP on any error, leaking the LDAP replication secret. This pins
// the enrollment client: no CA -> fail closed; foreign CA -> TLS
// handshake failure with no request reaching the server; matching CA
// -> verified HTTPS succeeds. (The full enroll path also installs the
// CSR response to hardcoded on-disk paths, so it is not exercised
// here; only the client/verification layer is.)
func TestEnrollPKIClientVerifiedHTTPSOnly(t *testing.T) {
	// No CA material at all: fail closed, naming the refusal.
	if _, err := enrollPKIClient([]string{filepath.Join(t.TempDir(), "nope.crt")}); err == nil {
		t.Fatal("enrollPKIClient must fail closed with no CA certificate")
	} else if !strings.Contains(err.Error(), "never falls back to plaintext HTTP") {
		t.Fatalf("fail-closed error should state the no-downgrade rule, got: %v", err)
	}

	pki := makeTestPKI(t)
	hits := 0
	srvCfg := pki.tlsConfig(t)
	// Enrollment is pre-PKI: the node has no client cert yet, so the
	// enroll endpoint authenticates by token, not mTLS. Drop the
	// client-cert requirement for this test server; the property
	// under test is the client's verification of the server.
	srvCfg.ClientAuth = tls.NoClientCert
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = srvCfg
	srv.StartTLS()
	defer srv.Close()

	// Foreign CA: the handshake must fail and no request — plain or
	// otherwise — may reach the server.
	foreign := makeTestPKI(t)
	foreignClient, err := enrollPKIClient([]string{foreign.caCert})
	if err != nil {
		t.Fatalf("enrollPKIClient with a foreign CA file should build: %v", err)
	}
	if _, err := foreignClient.Get(srv.URL + "/api/v1/sync/pki-enroll"); err == nil {
		t.Fatal("enrollment client must reject a peer presenting a foreign-CA certificate")
	}
	if hits != 0 {
		t.Fatalf("foreign-CA attempt reached the server handler %d times; nothing may be sent without verification", hits)
	}

	// Matching CA: verified HTTPS succeeds.
	client, err := enrollPKIClient([]string{pki.caCert})
	if err != nil {
		t.Fatalf("enrollPKIClient with the matching CA should build: %v", err)
	}
	resp, err := client.Get(srv.URL + "/api/v1/sync/pki-enroll")
	if err != nil {
		t.Fatalf("enrollment client with the matching CA should complete verified HTTPS: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits != 1 {
		t.Fatalf("expected one verified HTTPS request, got status=%d hits=%d", resp.StatusCode, hits)
	}
}

func TestSqliteSyncFailClosedOnCorruptOrExpiredPKI(t *testing.T) {
	origCA, origCert, origKey := syncHAPKICACertPath, syncHAPKINodeCertPath, syncHAPKINodeKeyPath
	t.Cleanup(func() {
		syncHAPKICACertPath = origCA
		syncHAPKINodeCertPath = origCert
		syncHAPKINodeKeyPath = origKey
	})

	// Helper to reserve an ephemeral port for startMasterServer error checks.
	freePort := func(t *testing.T) int {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		return p
	}

	// 1. Missing all enrollment certs (os.ErrNotExist): falls back to http for bootstrap enrollment.
	missingDir := t.TempDir()
	syncHAPKICACertPath = filepath.Join(missingDir, "ca.crt")
	syncHAPKINodeCertPath = filepath.Join(missingDir, "node.crt")
	syncHAPKINodeKeyPath = filepath.Join(missingDir, "node.key")

	mMissing := newMTLSManager()
	_, schemeMissing := mMissing.peerClient(2 * time.Second)
	if schemeMissing != "http" {
		t.Fatalf("expected http fallback when enrollment PKI is absent, got %q", schemeMissing)
	}

	// 2. Corrupt node certificate when PKI files exist: fail closed (never downgrade to http).
	pki := makeTestPKI(t)
	syncHAPKICACertPath = pki.caCert
	syncHAPKINodeCertPath = pki.nodeCert
	syncHAPKINodeKeyPath = pki.nodeKey

	// Valid PKI works over https.
	mValid := newMTLSManager()
	_, schemeValid := mValid.peerClient(2 * time.Second)
	if schemeValid != "https" {
		t.Fatalf("expected https with valid PKI, got %q", schemeValid)
	}

	// Corrupt node.crt -> peerClient stays https & fails requests, startMasterServer refuses cleartext fallback.
	if err := os.WriteFile(pki.nodeCert, []byte("not-a-valid-pem-cert"), 0644); err != nil {
		t.Fatal(err)
	}
	clientCorrupt, schemeCorrupt := mValid.peerClient(2 * time.Second)
	if schemeCorrupt != "https" {
		t.Fatalf("expected fail-closed https scheme on corrupt PKI, got %q", schemeCorrupt)
	}
	if _, err := clientCorrupt.Get("https://127.0.0.1:1/api/v1/sync/status"); err == nil || !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("expected fail-closed error from corrupt peerClient, got: %v", err)
	}
	mMasterCorrupt := newMTLSManager()
	mMasterCorrupt.cfg.LocalAddress = "127.0.0.1"
	mMasterCorrupt.cfg.ListenPort = freePort(t)
	mMasterCorrupt.mu.Lock()
	errMasterCorrupt := mMasterCorrupt.startMasterServer()
	mMasterCorrupt.mu.Unlock()
	if errMasterCorrupt == nil {
		mMasterCorrupt.Stop()
		t.Fatal("expected startMasterServer to fail closed on corrupt PKI instead of downgrading to token-http")
	}

	// 3. Partial PKI (node.crt present without node.key): fail closed.
	pkiPartial := makeTestPKI(t)
	syncHAPKICACertPath = pkiPartial.caCert
	syncHAPKINodeCertPath = pkiPartial.nodeCert
	syncHAPKINodeKeyPath = pkiPartial.nodeKey
	if err := os.Remove(pkiPartial.nodeKey); err != nil {
		t.Fatal(err)
	}
	clientPartial, schemePartial := mValid.peerClient(2 * time.Second)
	if schemePartial != "https" {
		t.Fatalf("expected https fail-closed when node.key removed, got %q", schemePartial)
	}
	if _, err := clientPartial.Get("https://127.0.0.1:1/api/v1/sync/status"); err == nil {
		t.Fatal("expected fail-closed error when node.key removed")
	}

	// 4. Expired node certificate: fail closed on both peerClient and startMasterServer.
	pkiExpired := makeTestPKI(t)
	syncHAPKICACertPath = pkiExpired.caCert
	syncHAPKINodeCertPath = pkiExpired.nodeCert
	syncHAPKINodeKeyPath = pkiExpired.nodeKey

	caBytes, _ := os.ReadFile(pkiExpired.caCert)
	caBlock, _ := pem.Decode(caBytes)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	caKeyBytes, _ := os.ReadFile(pkiExpired.caKey)
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	caKey, _ := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	expKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "expired-node"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &expKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(expKey)
	_ = os.WriteFile(pkiExpired.nodeCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	_ = os.WriteFile(pkiExpired.nodeKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)

	clientExp, schemeExp := mValid.peerClient(2 * time.Second)
	if schemeExp != "https" {
		t.Fatalf("expected https fail-closed on expired node cert, got %q", schemeExp)
	}
	if _, err := clientExp.Get("https://127.0.0.1:1/api/v1/sync/status"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error from fail-closed peerClient, got: %v", err)
	}
	mMasterExp := newMTLSManager()
	mMasterExp.cfg.LocalAddress = "127.0.0.1"
	mMasterExp.cfg.ListenPort = freePort(t)
	mMasterExp.mu.Lock()
	errMasterExp := mMasterExp.startMasterServer()
	mMasterExp.mu.Unlock()
	if errMasterExp == nil || !strings.Contains(errMasterExp.Error(), "expired") {
		if errMasterExp == nil {
			mMasterExp.Stop()
		}
		t.Fatalf("expected startMasterServer to fail closed on expired cert, got: %v", errMasterExp)
	}
}
