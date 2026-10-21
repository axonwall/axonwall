package engine

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	m := NewSqliteSyncManager()
	m.cfg = SqliteSyncConfig{Transport: "token-http"}
	if m.mtlsRequested() {
		t.Fatal("mtlsRequested should be false for transport 'token-http'")
	}
}
