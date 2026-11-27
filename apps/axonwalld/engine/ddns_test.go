package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDDNSClientHardening(t *testing.T) {
	var targetHits int
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+"/redirected", http.StatusFound)
	}))
	defer redirSrv.Close()

	// Default DdnsManager blocks loopback and IMDS.
	dm := NewDdnsManager()
	if err := dm.ApplyConfigJSON([]byte(fmt.Sprintf(`{"enabled": true, "entries": [
		{"provider": "custom", "hostname": "host.example.com", "customUpdateUrl": %q, "enabled": true}
	]}`, targetSrv.URL+"/hook"))); err != nil {
		t.Fatalf("ApplyConfigJSON: %v", err)
	}
	st := dm.TriggerSyncNow()
	if targetHits != 0 {
		t.Fatalf("expected default DdnsManager to block 127.0.0.1, got %d hits", targetHits)
	}
	if !strings.Contains(st.Entries[0].LastStatusMsg, "Webhook error:") {
		t.Fatalf("expected error status on blocked loopback, got %q", st.Entries[0].LastStatusMsg)
	}

	if err := dm.ApplyConfigJSON([]byte(`{"enabled": true, "entries": [
		{"provider": "custom", "hostname": "host.example.com", "customUpdateUrl": "http://169.254.169.254/latest/meta-data/", "enabled": true}
	]}`)); err != nil {
		t.Fatalf("ApplyConfigJSON IMDS: %v", err)
	}
	stIMDS := dm.TriggerSyncNow()
	if !strings.Contains(stIMDS.Entries[0].LastStatusMsg, "Webhook error:") {
		t.Fatalf("expected IMDS target to fail, got %q", stIMDS.Entries[0].LastStatusMsg)
	}

	// Even with loopback enabled for test, redirects must be refused and not followed.
	dm.SetAllowLoopbackForTest(true)
	if err := dm.ApplyConfigJSON([]byte(fmt.Sprintf(`{"enabled": true, "entries": [
		{"provider": "custom", "hostname": "host.example.com", "customUpdateUrl": %q, "enabled": true}
	]}`, redirSrv.URL))); err != nil {
		t.Fatalf("ApplyConfigJSON redirect: %v", err)
	}
	stRedir := dm.TriggerSyncNow()
	if targetHits != 0 {
		t.Fatalf("expected redirect target not to be reached, got %d hits", targetHits)
	}
	if !strings.Contains(stRedir.Entries[0].LastStatusMsg, "HTTP 302") {
		t.Fatalf("expected unfollowed 302 failure status, got %q", stRedir.Entries[0].LastStatusMsg)
	}
}
