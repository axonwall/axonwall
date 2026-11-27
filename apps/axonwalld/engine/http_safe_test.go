package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestSafeHTTPClientBlocksSSRFRangesAndRedirects(t *testing.T) {
	blockedAddrs := []struct {
		ip            string
		allowLoopback bool
		wantBlocked   bool
	}{
		{"169.254.169.254", true, true},
		{"169.254.1.1", true, true},
		{"fe80::1", true, true},
		{"0.0.0.0", true, true},
		{"0.1.2.3", true, true},
		{"100::1", true, true},
		{"2001:db8::1", true, true},
		{"2002::1", true, true},
		{"2001::1", true, true},
		{"64:ff9b:1::1", true, true},
		{"::ffff:127.0.0.1", true, true},
		{"::ffff:169.254.169.254", true, true},
		{"::ffff:1.1.1.1", true, true},
		{"fec0::1", true, true},
		{"fd00:ec2::254", true, true},
		{"127.0.0.1", false, true},
		{"::1", false, true},
		{"127.0.0.1", true, false},
		{"::1", true, false},
		{"1.1.1.1", false, false},
		{"10.0.0.5", false, false},
	}

	for _, tc := range blockedAddrs {
		addr := netip.MustParseAddr(tc.ip)
		gotBlocked, reason := isBlockedSafeHTTPAddr(addr, tc.allowLoopback, false)
		if gotBlocked != tc.wantBlocked {
			t.Fatalf("ip=%s allowLoopback=%v: blocked=%v (%s), want %v", tc.ip, tc.allowLoopback, gotBlocked, reason, tc.wantBlocked)
		}
	}

	// Ensure Go's 16-byte net.IP representation of normal IPv4 is not mistaken for ::ffff:0:0/96.
	v4NetIP := net.ParseIP("1.1.1.1")
	parsedV4, ok := netIPToSafeAddr(v4NetIP)
	if !ok {
		t.Fatal("netIPToSafeAddr failed for 1.1.1.1")
	}
	if blocked, reason := isBlockedSafeHTTPAddr(parsedV4, false, false); blocked {
		t.Fatalf("normal IPv4 1.1.1.1 falsely blocked: %s", reason)
	}

	var targetHits int
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+"/secret", http.StatusFound)
	}))
	defer redirSrv.Close()

	// Default client blocks loopback.
	defaultClient, defaultTr := newSafeHTTPClient(SafeHTTPClientOptions{Timeout: 2 * time.Second})
	defer defaultTr.CloseIdleConnections()
	if _, err := defaultClient.Get(targetSrv.URL); err == nil {
		t.Fatal("expected default safe HTTP client to block 127.0.0.1 loopback")
	}
	if _, err := defaultClient.Get("http://[::ffff:127.0.0.1]:80/"); err == nil {
		t.Fatal("expected default safe HTTP client to block ::ffff:127.0.0.1")
	}
	if _, err := defaultClient.Get("http://localhost:80/"); err == nil {
		t.Fatal("expected default safe HTTP client to block localhost")
	}
	if _, err := defaultClient.Get("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Fatal("expected default safe HTTP client to block IMDS 169.254.169.254")
	}

	// With AllowLoopback=true, loopback works, but redirects are still refused via ErrUseLastResponse.
	loopbackClient, loopbackTr := newSafeHTTPClient(SafeHTTPClientOptions{
		Timeout:       2 * time.Second,
		AllowLoopback: true,
	})
	defer loopbackTr.CloseIdleConnections()
	resp, err := loopbackClient.Get(redirSrv.URL)
	if err != nil {
		t.Fatalf("expected non-followed 302 response with ErrUseLastResponse, got err: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 status returned unfollowed, got %d", resp.StatusCode)
	}
	if targetHits != 0 {
		t.Fatalf("expected redirect target never to be hit, got %d hits", targetHits)
	}
	if _, err := loopbackClient.Get("http://[::ffff:127.0.0.1]:80/"); err == nil {
		t.Fatal("expected ::ffff:127.0.0.1 blocked even when AllowLoopback=true")
	}
}
