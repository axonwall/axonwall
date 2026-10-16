package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAgentTokenHTTPMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := agentTokenHTTPMiddleware("s3cret-token", next)

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "nope", http.StatusUnauthorized},
		{"correct token", "s3cret-token", http.StatusOK},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
		if tc.header != "" {
			req.Header.Set(agentTokenHeader, tc.header)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

func TestAgentTokenInterceptors(t *testing.T) {
	unary := agentTokenUnaryInterceptor("s3cret-token")
	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}

	if _, err := unary(context.Background(), nil, &grpc.UnaryServerInfo{}, handler); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no metadata: got %v, want Unauthenticated", err)
	}
	if called {
		t.Error("handler must not run without a token")
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(agentTokenMetadata, "wrong"))
	if _, err := unary(ctx, nil, &grpc.UnaryServerInfo{}, handler); status.Code(err) != codes.Unauthenticated {
		t.Errorf("wrong token: got %v, want Unauthenticated", err)
	}

	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs(agentTokenMetadata, "s3cret-token"))
	if _, err := unary(ctx, nil, &grpc.UnaryServerInfo{}, handler); err != nil {
		t.Errorf("correct token: got %v, want nil", err)
	}
	if !called {
		t.Error("handler must run with the correct token")
	}
}

func TestResolveAgentTokenGeneratesAndPersists(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "agent.token")
	t.Setenv("AXONWALL_AGENT_TOKEN", "")
	t.Setenv("AXONWALL_AGENT_TOKEN_FILE", tokenPath)

	tok, source := resolveAgentToken()
	if len(tok) != 64 {
		t.Errorf("expected a 64-char hex token, got %d chars", len(tok))
	}
	if !strings.Contains(source, "generated") {
		t.Errorf("expected generated source, got %q", source)
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("token was not persisted: %v", err)
	}
	if strings.TrimSpace(string(data)) != tok {
		t.Error("persisted token does not match the returned token")
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0007 != 0 {
		t.Errorf("token file must not be world-accessible, got perm %o", perm)
	}

	// Second resolution loads the same token from disk.
	tok2, source2 := resolveAgentToken()
	if tok2 != tok || !strings.Contains(source2, "file") {
		t.Errorf("expected token to load from file, got source %q", source2)
	}

	// Environment wins over the file.
	t.Setenv("AXONWALL_AGENT_TOKEN", "from-env")
	if tok3, _ := resolveAgentToken(); tok3 != "from-env" {
		t.Errorf("expected env token to win, got %q", tok3)
	}
}
