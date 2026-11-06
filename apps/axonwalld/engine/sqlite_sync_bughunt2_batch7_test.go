package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serveDb returns a peer server that serves content as the /api/v1/sync/db
// payload with a correct checksum header.
func serveDb(t *testing.T, content []byte) (*httptest.Server, int) {
	t.Helper()
	sum := sha256.Sum256(content)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Checksum-SHA256", hex.EncodeToString(sum[:]))
		_, _ = w.Write(content)
	}))
	t.Cleanup(peer.Close)
	peerURL, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	peerPort := 0
	fmt.Sscanf(strings.Split(peerURL.Host, ":")[1], "%d", &peerPort)
	return peer, peerPort
}

func newTestSyncManager(t *testing.T, localDb string, peerPort int) *SqliteSyncManager {
	t.Helper()
	m := NewSqliteSyncManager()
	cfg := SqliteSyncConfig{
		Enabled:             true,
		NodeRole:            "backup",
		Mode:                "direct_stream",
		Databases:           []string{localDb},
		SyncIntervalSeconds: 3600,
		ListenPort:          0,
		PeerAddress:         "127.0.0.1",
		PeerPort:            peerPort,
		AuthToken:           "test-token",
	}
	if err := m.ApplyConfig(cfg); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	t.Cleanup(m.Stop)
	return m
}

// A-M17: a downloaded database that is not a valid SQLite database must
// never replace the live one, even with a correct checksum.
func TestBatch7_FetchAndApplyDbRejectsInvalidSqlite(t *testing.T) {
	localDir, err := os.MkdirTemp("/var/lib/axonwall", "bughunt2-m17-")
	if err != nil {
		t.Skipf("cannot create fixture dir under /var/lib/axonwall: %v", err)
	}
	defer os.RemoveAll(localDir)
	localDb := filepath.Join(localDir, "headscale.db")
	original := []byte("local-master-content")
	if err := os.WriteFile(localDb, original, 0600); err != nil {
		t.Fatal(err)
	}

	_, peerPort := serveDb(t, []byte("peer-database-content-that-is-not-sqlite"))
	m := newTestSyncManager(t, localDb, peerPort)

	stopCh := make(chan struct{})
	err = m.fetchAndApplyDb(localDb, peerPort, http.DefaultClient, "http", stopCh, context.Background())
	if err == nil {
		t.Fatal("fetchAndApplyDb with a non-SQLite payload returned nil, want error")
	}

	got, err := os.ReadFile(localDb)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("local database was overwritten by an invalid payload: got %q", got)
	}
	if _, err := os.Stat(localDb + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("invalid apply left a .bak behind (or stat failed): %v", err)
	}
}

// A-M17: a valid SQLite peer database applies, and the replaced local
// database is kept as .bak for rollback.
func TestBatch7_FetchAndApplyDbKeepsBackupOfReplacedDb(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 CLI not available to build a valid fixture database")
	}
	localDir, err := os.MkdirTemp("/var/lib/axonwall", "bughunt2-m17-")
	if err != nil {
		t.Skipf("cannot create fixture dir under /var/lib/axonwall: %v", err)
	}
	defer os.RemoveAll(localDir)
	localDb := filepath.Join(localDir, "headscale.db")
	original := []byte("local-master-content")
	if err := os.WriteFile(localDb, original, 0600); err != nil {
		t.Fatal(err)
	}

	peerDb := filepath.Join(localDir, "peer.db")
	if out, err := exec.Command("sqlite3", peerDb, "CREATE TABLE t(x); INSERT INTO t VALUES (1);").CombinedOutput(); err != nil {
		t.Fatalf("building fixture peer db: %s (%v)", out, err)
	}
	peerContent, err := os.ReadFile(peerDb)
	if err != nil {
		t.Fatal(err)
	}

	_, peerPort := serveDb(t, peerContent)
	m := newTestSyncManager(t, localDb, peerPort)

	stopCh := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.fetchAndApplyDb(localDb, peerPort, http.DefaultClient, "http", stopCh, ctx); err != nil {
		t.Fatalf("fetchAndApplyDb with a valid SQLite payload: %v", err)
	}

	got, err := os.ReadFile(localDb)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(peerContent) {
		t.Fatal("local database was not replaced by the valid peer database")
	}
	bak, err := os.ReadFile(localDb + ".bak")
	if err != nil {
		t.Fatalf("replaced database was not kept as .bak: %v", err)
	}
	if string(bak) != string(original) {
		t.Fatalf(".bak content = %q, want original %q", bak, original)
	}
}
