package engine

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// The HA sync endpoints serve the headscale database, appliance state, ZFS
// send streams and the K3s join token. Authentication must fail closed:
// with no token configured, every request is rejected (regression test for
// the previous fail-open `if authToken != ""` checks).
func TestSqliteSyncHandlersFailClosed(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "headscale.sqlite")
	if err := os.WriteFile(dbFile, []byte("fake-db"), 0600); err != nil {
		t.Fatal(err)
	}

	newManager := func(token string) *SqliteSyncManager {
		m := NewSqliteSyncManager()
		m.cfg = SqliteSyncConfig{
			Enabled:    true,
			NodeRole:   "master",
			AuthToken:  token,
			Databases:  []string{dbFile},
			ListenPort: 9876,
		}
		return m
	}

	serverHandlers := map[string]func(*SqliteSyncManager, http.ResponseWriter, *http.Request){
		"status":    (*SqliteSyncManager).handleStatus,
		"db":        (*SqliteSyncManager).handleDownloadDb,
		"state":     (*SqliteSyncManager).handleDownloadState,
		"zfs":       (*SqliteSyncManager).handleZfsSendStream,
		"k3s-token": (*SqliteSyncManager).handleK3sToken,
	}

	call := func(m *SqliteSyncManager, h func(*SqliteSyncManager, http.ResponseWriter, *http.Request), token string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sync/status", nil)
		if token != "" {
			req.Header.Set("X-Axonwall-Sync-Token", token)
		}
		rec := httptest.NewRecorder()
		h(m, rec, req)
		return rec.Code
	}

	for name, h := range serverHandlers {
		// No token configured: everything is rejected, even a request
		// that presents some token.
		if code := call(newManager(""), h, ""); code != http.StatusUnauthorized {
			t.Errorf("%s: no configured token, no header: got %d, want 401", name, code)
		}
		if code := call(newManager(""), h, "anything"); code != http.StatusUnauthorized {
			t.Errorf("%s: no configured token, bogus header: got %d, want 401", name, code)
		}
		// Token configured: wrong or missing token is rejected.
		if code := call(newManager("s3cret"), h, ""); code != http.StatusUnauthorized {
			t.Errorf("%s: configured token, no header: got %d, want 401", name, code)
		}
		if code := call(newManager("s3cret"), h, "wrong"); code != http.StatusUnauthorized {
			t.Errorf("%s: configured token, wrong header: got %d, want 401", name, code)
		}
	}

	// Correct token passes the auth gate on the status endpoint (which
	// only stats the configured database files).
	if code := call(newManager("s3cret"), (*SqliteSyncManager).handleStatus, "s3cret"); code != http.StatusOK {
		t.Errorf("status: correct token: got %d, want 200", code)
	}
}

func TestSqliteSyncZfsValidation(t *testing.T) {
	m := NewSqliteSyncManager()
	m.cfg = SqliteSyncConfig{
		Enabled:   true,
		NodeRole:  "master",
		AuthToken: "s3cret",
	}

	callZfs := func(dataset, from string) int {
		q := url.Values{}
		q.Set("dataset", dataset)
		if from != "" {
			q.Set("from", from)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sync/zfs?"+q.Encode(), nil)
		req.Header.Set("X-Axonwall-Sync-Token", "s3cret")
		rec := httptest.NewRecorder()
		m.handleZfsSendStream(rec, req)
		return rec.Code
	}

	// Malicious dataset parameters
	if code := callZfs("-v", ""); code != http.StatusBadRequest {
		t.Errorf("leading hyphen dataset: got %d, want 400", code)
	}
	if code := callZfs("pool/data;rm -rf /", ""); code != http.StatusBadRequest {
		t.Errorf("semicolon dataset: got %d, want 400", code)
	}
	if code := callZfs("pool/data", "-R"); code != http.StatusBadRequest {
		t.Errorf("leading hyphen fromSnap: got %d, want 400", code)
	}
	if code := callZfs("pool/data", "snap@extra@parts"); code != http.StatusBadRequest {
		t.Errorf("invalid fromSnap: got %d, want 400", code)
	}
}
