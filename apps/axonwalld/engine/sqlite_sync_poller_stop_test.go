package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A-H3 regression: a backup poller mid-download must not apply a peer
// database after the node has become MASTER. Pre-fix, stopInternal
// only closed the stop channel and OnStateChange started the master
// server immediately, so the in-flight download renamed the peer DB
// over the live file (and dropped its WAL) after takeover. Post-fix,
// OnStateChange joins the poller (whose HTTP requests are cancelled
// on stop) before starting the master server, so the local file is
// untouched even once the peer download is released.
func TestPollerDoesNotApplyDbAfterMasterTransition(t *testing.T) {
	// fetchAndApplyDb only applies databases under /var/lib/axonwall/,
	// so the fixture DB must live there (cleaned up by RemoveAll).
	localDir, err := os.MkdirTemp("/var/lib/axonwall", "bughunt-ah3-")
	if err != nil {
		t.Skipf("cannot create fixture dir under /var/lib/axonwall (test needs the daemon's DB prefix): %v", err)
	}
	defer os.RemoveAll(localDir)
	localDb := filepath.Join(localDir, "headscale.db")
	original := []byte("local-master-content")
	if err := os.WriteFile(localDb, original, 0600); err != nil {
		t.Fatal(err)
	}
	peerContent := []byte("peer-database-content")
	peerSum := sha256.Sum256(peerContent)
	peerSha := hex.EncodeToString(peerSum[:])

	downloadStarted := make(chan struct{})
	releaseDownload := make(chan struct{})
	var downloadOnce bool
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/sync/status":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"nodeRole":"master","timestamp":1,"databases":[{"path":%q,"size":%d,"sha256":%q,"modTime":1}]}`, localDb, len(peerContent), peerSha)
		case "/api/v1/sync/db":
			if !downloadOnce {
				downloadOnce = true
				close(downloadStarted)
			}
			select {
			case <-releaseDownload:
			case <-r.Context().Done():
				return
			case <-time.After(30 * time.Second):
				t.Error("peer db download was neither released nor cancelled")
				return
			}
			w.Header().Set("X-Checksum-SHA256", peerSha)
			_, _ = w.Write(peerContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer peer.Close()

	peerURL, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	peerPort := 0
	fmt.Sscanf(strings.Split(peerURL.Host, ":")[1], "%d", &peerPort)

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
	defer m.Stop()

	// Wait until the poller is blocked inside the peer DB download.
	select {
	case <-downloadStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("poller never started the peer DB download")
	}

	// Flip to MASTER while the download is still in flight. This must
	// return promptly (the cancelled download must not stall it) and,
	// crucially, must not let the download land afterwards.
	masterDone := make(chan struct{})
	go func() {
		defer close(masterDone)
		m.OnStateChange("MASTER")
	}()
	select {
	case <-masterDone:
	case <-time.After(15 * time.Second):
		t.Fatal("OnStateChange(MASTER) did not return while the poller download was in flight")
	}

	// Now release the peer download: pre-fix code renames it over the
	// local DB here; post-fix code has already aborted the poller.
	close(releaseDownload)
	time.Sleep(500 * time.Millisecond)

	got, err := os.ReadFile(localDb)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("local database was overwritten after MASTER transition: got %q, want original %q", got, original)
	}
}
