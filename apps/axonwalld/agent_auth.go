package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Agent API authentication.
//
// axonwalld's control surface -- ApplyBundle (arbitrary nftables as
// root), a bash terminal, NAS/K3s/HA management -- is served over two
// Unix sockets (gRPC and HTTP REST). Historically the only access
// control was the socket file mode (0660, group "axonwall"), and the
// daemon performed no caller authentication of its own: any process
// able to open the socket was root-equivalent. The daemon now
// additionally requires a per-install shared token on every call:
//
//   - AXONWALL_AGENT_TOKEN (environment) wins when set.
//   - Otherwise the token is read from /etc/axonwall/agent.token
//     (AXONWALL_AGENT_TOKEN_FILE overrides the path).
//   - On first start the daemon generates a random token and
//     persists it 0640 root:axonwall so the on-box control-plane
//     services (UI, controller) can read it while other local users
//     cannot. If persistence fails it falls back to an ephemeral
//     token and logs loudly; clients must then share the token via
//     the environment.
//
// The socket permissions stay as they were -- the token is a second,
// independent factor that also survives accidental socket exposure
// (bind mounts, container volume sharing, permission regressions).
const (
	agentTokenHeader   = "X-Axonwall-Agent-Token"
	agentTokenMetadata = "x-axonwall-agent-token"
	defaultAgentToken  = "/etc/axonwall/agent.token"
)

var (
	runtimeSocketGroup string
	currentRuntimeMode = engine.ModeAppliance
)

func resolveSocketGroupGID() int {
	lookupNameOrGID := func(name string) int {
		if name == "" {
			return -1
		}
		if grp, err := user.LookupGroup(name); err == nil {
			if gid, err := strconv.Atoi(grp.Gid); err == nil {
				return gid
			}
		}
		if gid, err := strconv.Atoi(name); err == nil && gid >= 0 {
			return gid
		}
		return -1
	}

	if explicit := strings.TrimSpace(runtimeSocketGroup); explicit != "" {
		if gid := lookupNameOrGID(explicit); gid >= 0 {
			return gid
		}
	}
	if envGroup := strings.TrimSpace(os.Getenv("AXONWALL_SOCKET_GROUP")); envGroup != "" {
		if gid := lookupNameOrGID(envGroup); gid >= 0 {
			return gid
		}
	}
	if gid := lookupNameOrGID("axonwall-api"); gid >= 0 {
		return gid
	}
	if gid := lookupNameOrGID("axonwall"); gid >= 0 {
		return gid
	}
	if currentRuntimeMode == engine.ModeHost || currentRuntimeMode == engine.ModeDev {
		if sudoGidStr := strings.TrimSpace(os.Getenv("SUDO_GID")); sudoGidStr != "" {
			if gid, err := strconv.Atoi(sudoGidStr); err == nil && gid > 0 {
				return gid
			}
		}
		if gid := lookupNameOrGID("wheel"); gid >= 0 {
			return gid
		}
		if gid := lookupNameOrGID("sudo"); gid >= 0 {
			return gid
		}
	}
	return -1
}

// resolveAgentTokenPath returns the active persistent token path, honoring
// AXONWALL_AGENT_TOKEN_FILE and AXONWALL_ETC_DIR before /etc/axonwall/agent.token.
func resolveAgentTokenPath() string {
	if p := strings.TrimSpace(os.Getenv("AXONWALL_AGENT_TOKEN_FILE")); p != "" {
		return p
	}
	if etcDir := strings.TrimSpace(os.Getenv("AXONWALL_ETC_DIR")); etcDir != "" {
		return filepath.Join(etcDir, "agent.token")
	}
	return defaultAgentToken
}

// resolveAgentToken returns the daemon's agent API token and a short
// description of where it came from.
func resolveAgentToken() (string, string) {
	if env := strings.TrimSpace(os.Getenv("AXONWALL_AGENT_TOKEN")); env != "" {
		return env, "environment"
	}

	path := resolveAgentTokenPath()
	if data, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(data)); tok != "" {
			return tok, "file " + path
		}
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("[Agent] Failed to generate agent API token: %v", err)
	}
	tok := hex.EncodeToString(buf)
	if err := persistAgentToken(path, tok); err != nil {
		log.Printf("[Agent] WARNING: could not persist agent API token to %s (%v); using an ephemeral token for this run -- clients must be given the same token via AXONWALL_AGENT_TOKEN", path, err)
		return tok, "ephemeral (not persisted)"
	}
	return tok, "generated file " + path
}

func persistAgentToken(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	perm := os.FileMode(0600)
	gid := resolveSocketGroupGID()
	if gid >= 0 {
		perm = 0640
	}
	if err := os.WriteFile(path, []byte(token+"\n"), perm); err != nil {
		return err
	}
	_ = os.Chmod(path, perm)
	if gid >= 0 {
		_ = os.Chown(path, -1, gid)
	}
	return nil
}

func writeRuntimeTokenCopy(sockDir, token string) {
	if sockDir == "" || token == "" {
		return
	}
	rtPath := filepath.Join(sockDir, "agent.token")
	if err := persistAgentToken(rtPath, token); err != nil {
		log.Printf("[Agent] Warning: could not write runtime token copy to %s: %v", rtPath, err)
	}
}

func chownSocketToAPIGroup(path string, mode os.FileMode) {
	_ = os.Chmod(path, mode)
	if gid := resolveSocketGroupGID(); gid >= 0 {
		_ = os.Chown(path, -1, gid)
	}
}

func agentTokenValid(provided, expected string) bool {
	if provided == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func agentTokenHTTPMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !agentTokenValid(r.Header.Get(agentTokenHeader), token) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "unauthorized: valid " + agentTokenHeader + " required",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func checkAgentTokenMetadata(ctx context.Context, token string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing RPC metadata")
	}
	values := md.Get(agentTokenMetadata)
	if len(values) == 0 || !agentTokenValid(values[0], token) {
		return status.Error(codes.Unauthenticated, "valid "+agentTokenMetadata+" required")
	}
	return nil
}

func agentTokenUnaryInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := checkAgentTokenMetadata(ctx, token); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func agentTokenStreamInterceptor(token string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkAgentTokenMetadata(ss.Context(), token); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
