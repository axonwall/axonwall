package engine

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestObservabilityScrapeTokenConstantTimeAuth(t *testing.T) {
	// Reserve an ephemeral localhost port cleanly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	m := NewMetricsShipper(nil, nil, nil, nil)
	bundle := &ObservabilityRuntimeBundle{
		NodeID:   "node-1",
		Hostname: "fw-1",
		Enabled:  true,
	}
	bundle.Offload.Metrics.ExposeScrape = true
	bundle.Offload.Metrics.ScrapeBind = "127.0.0.1"
	bundle.Offload.Metrics.ScrapePort = port
	bundle.Offload.Metrics.ScrapeToken = "super-secret-scrape-token"
	m.ApplyConfig(bundle)
	t.Cleanup(m.Stop)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	client := &http.Client{Timeout: time.Second}

	// Wait briefly for the scrape listener goroutine to bind.
	var ready bool
	for i := 0; i < 30; i++ {
		resp, err := client.Get(baseURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("metrics scrape listener did not become ready with 401 on unauthenticated request")
	}

	for _, badAuth := range []string{
		"",
		"Bearer wrong-token",
		"Bearer super-secret-scrape-tok",
		"Basic super-secret-scrape-token",
	} {
		req, _ := http.NewRequest(http.MethodGet, baseURL, nil)
		if badAuth != "" {
			req.Header.Set("Authorization", badAuth)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("auth=%q: expected 401, got %d", badAuth, resp.StatusCode)
		}
	}

	reqOK, _ := http.NewRequest(http.MethodGet, baseURL, nil)
	reqOK.Header.Set("Authorization", "Bearer super-secret-scrape-token")
	respOK, err := client.Do(reqOK)
	if err != nil {
		t.Fatalf("authenticated scrape request failed: %v", err)
	}
	_ = respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid Bearer token, got %d", respOK.StatusCode)
	}
}

func TestObservabilityShipperHTTPClientHardening(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redir.Close()

	cfg := &ObservabilityRuntimeBundle{}
	defaultClient, defaultTr, err := buildObservabilityHTTPClient(cfg, target.URL)
	if err != nil {
		t.Fatalf("buildObservabilityHTTPClient: %v", err)
	}
	defer defaultTr.CloseIdleConnections()

	if _, err := defaultClient.Post(target.URL, "application/x-protobuf", strings.NewReader("x")); err == nil {
		t.Fatal("expected buildObservabilityHTTPClient to block loopback by default")
	}
	if _, err := defaultClient.Post("http://169.254.169.254/latest/meta-data/", "application/x-protobuf", strings.NewReader("x")); err == nil {
		t.Fatal("expected buildObservabilityHTTPClient to block IMDS")
	}

	loopbackClient, loopbackTr, err := buildObservabilityHTTPClientWithOpts(cfg, redir.URL, true)
	if err != nil {
		t.Fatalf("buildObservabilityHTTPClientWithOpts: %v", err)
	}
	defer loopbackTr.CloseIdleConnections()
	resp, err := loopbackClient.Post(redir.URL, "application/x-protobuf", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("expected unfollowed 302 response, got err: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || targetHits != 0 {
		t.Fatalf("expected redirect not followed (status=%d, targetHits=%d)", resp.StatusCode, targetHits)
	}
}
