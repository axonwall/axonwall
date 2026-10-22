package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStatusAdvertisesSigningCapability pins the D-04 Phase 4b
// advertisement: the sync status reports signsPayloads exactly when the
// node can sign (the availability seam), and a pre-P4b peer's response
// (no such field) decodes as not advertising.
func TestStatusAdvertisesSigningCapability(t *testing.T) {
	orig := haPayloadSigningAvailable
	t.Cleanup(func() { haPayloadSigningAvailable = orig })

	m := NewSqliteSyncManager()
	m.cfg = SqliteSyncConfig{Enabled: true, NodeRole: "master", AuthToken: "tok"}

	getStatus := func() SyncStatusResponse {
		req := httptest.NewRequest("GET", "/api/v1/sync/status", nil)
		req.Header.Set("X-Axonwall-Sync-Token", "tok")
		rec := httptest.NewRecorder()
		m.handleStatus(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var st SyncStatusResponse
		if err := json.NewDecoder(rec.Body).Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	haPayloadSigningAvailable = func() bool { return true }
	if st := getStatus(); !st.SignsPayloads {
		t.Fatal("status must advertise signsPayloads when the node key is available")
	}

	haPayloadSigningAvailable = func() bool { return false }
	if st := getStatus(); st.SignsPayloads {
		t.Fatal("status must not advertise signsPayloads when the node cannot sign")
	}

	// A response from a pre-P4b build has no signsPayloads field at
	// all; it must decode as not advertising (gate stays off for it).
	var legacy SyncStatusResponse
	if err := json.Unmarshal([]byte(`{"nodeRole":"master","timestamp":1,"transport":"mtls","databases":[]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.SignsPayloads {
		t.Fatal("legacy status without the field must decode as not advertising")
	}
}
