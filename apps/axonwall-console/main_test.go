package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuessGateway(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		cidr     int
		expected string
	}{
		{
			name:     "Standard /24 subnet",
			ip:       "192.168.1.100",
			cidr:     24,
			expected: "192.168.1.1",
		},
		{
			name:     "Standard /24 with .1 entered as IP",
			ip:       "192.168.1.1",
			cidr:     24,
			expected: "192.168.1.254",
		},
		{
			name:     "Public WAN /24",
			ip:       "203.0.113.50",
			cidr:     24,
			expected: "203.0.113.1",
		},
		{
			name:     "/30 point-to-point (upper host)",
			ip:       "203.0.113.14",
			cidr:     30,
			expected: "203.0.113.13",
		},
		{
			name:     "/30 point-to-point (lower host)",
			ip:       "203.0.113.13",
			cidr:     30,
			expected: "203.0.113.14",
		},
		{
			name:     "/29 subnet (size 8)",
			ip:       "198.51.100.37",
			cidr:     29,
			expected: "198.51.100.33",
		},
		{
			name:     "/29 subnet with first usable IP",
			ip:       "198.51.100.33",
			cidr:     29,
			expected: "198.51.100.38",
		},
		{
			name:     "/28 subnet (size 16)",
			ip:       "10.20.30.25",
			cidr:     28,
			expected: "10.20.30.17",
		},
		{
			name:     "/31 RFC 3021 subnet (even host)",
			ip:       "10.0.0.2",
			cidr:     31,
			expected: "10.0.0.3",
		},
		{
			name:     "/31 RFC 3021 subnet (odd host)",
			ip:       "10.0.0.3",
			cidr:     31,
			expected: "10.0.0.2",
		},
		{
			name:     "/16 large subnet fills first 3 octets",
			ip:       "172.16.50.100",
			cidr:     16,
			expected: "172.16.50.1",
		},
		{
			name:     "/8 large subnet fills first 3 octets",
			ip:       "10.5.20.88",
			cidr:     8,
			expected: "10.5.20.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := guessGateway(tc.ip, tc.cidr)
			if result != tc.expected {
				t.Errorf("guessGateway(%q, %d) = %q; want %q", tc.ip, tc.cidr, result, tc.expected)
			}
		})
	}
}

func TestCIDRToNetmask(t *testing.T) {
	tests := []struct {
		cidr     int
		expected string
	}{
		{24, "255.255.255.0"},
		{30, "255.255.255.252"},
		{29, "255.255.255.248"},
		{28, "255.255.255.240"},
		{16, "255.255.0.0"},
		{8, "255.0.0.0"},
	}

	for _, tc := range tests {
		res := cidrToNetmask(tc.cidr)
		if res != tc.expected {
			t.Errorf("cidrToNetmask(%d) = %q; want %q", tc.cidr, res, tc.expected)
		}
	}
}

func TestHashAndVerifyPassword(t *testing.T) {
	pass := "SecureP@ssw0rd2026!"
	hashed, err := hashPassword(pass)
	if err != nil {
		t.Fatalf("hashPassword failed: %v", err)
	}
	if !strings.HasPrefix(hashed, "scrypt$") {
		t.Fatalf("expected hash prefix 'scrypt$', got: %s", hashed)
	}
	if !verifyPassword(pass, hashed) {
		t.Errorf("verifyPassword failed for valid password")
	}
	if verifyPassword("WrongPassword!", hashed) {
		t.Errorf("verifyPassword should fail for wrong password")
	}
}

func TestHashAndVerifySSHA(t *testing.T) {
	pass := "OpenLDAPAdmin2026!"
	hashed, err := hashSSHA(pass)
	if err != nil {
		t.Fatalf("hashSSHA failed: %v", err)
	}
	if !strings.HasPrefix(hashed, "{SSHA}") {
		t.Fatalf("expected hash prefix '{SSHA}', got: %s", hashed)
	}
	if !verifySSHA(pass, hashed) {
		t.Errorf("verifySSHA failed for valid password")
	}
	if verifySSHA("IncorrectPass", hashed) {
		t.Errorf("verifySSHA should fail for incorrect password")
	}
}

func TestUpdateAdminEnvPassword(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "admin.env")

	// 1. Initial write
	updateAdminEnvPassword(envPath, "admin", "hash1")
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read admin.env: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "LOCAL_ADMIN_USER=admin") || !strings.Contains(content, "LOCAL_ADMIN_PASSWORD=hash1") {
		t.Errorf("unexpected content: %s", content)
	}

	// 2. Overwrite / update password preserving user
	updateAdminEnvPassword(envPath, "admin", "hash2")
	data, err = os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read admin.env: %v", err)
	}
	content = string(data)
	if !strings.Contains(content, "LOCAL_ADMIN_PASSWORD=hash2") || strings.Contains(content, "LOCAL_ADMIN_PASSWORD=hash1") {
		t.Errorf("password was not updated correctly: %s", content)
	}
}

func TestUpdateAxonwallEnvPassword(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "axonwall.env")
	initialContent := "JWT_SECRET=abc123secret\nLOCAL_ADMIN_USER=admin\nLOCAL_ADMIN_PASSWORD=oldhash\nAGENT_API_SOCKET=/run/axonwall/agent-api.sock\n"
	if err := os.WriteFile(envPath, []byte(initialContent), 0600); err != nil {
		t.Fatalf("failed to write initial axonwall.env: %v", err)
	}

	updateAxonwallEnvPassword(envPath, "newhash456")
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read updated axonwall.env: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "JWT_SECRET=abc123secret") {
		t.Errorf("JWT_SECRET was lost: %s", content)
	}
	if !strings.Contains(content, "AGENT_API_SOCKET=/run/axonwall/agent-api.sock") {
		t.Errorf("AGENT_API_SOCKET was lost: %s", content)
	}
	if !strings.Contains(content, "LOCAL_ADMIN_PASSWORD=newhash456") {
		t.Errorf("LOCAL_ADMIN_PASSWORD was not updated: %s", content)
	}
	if strings.Contains(content, "LOCAL_ADMIN_PASSWORD=oldhash") {
		t.Errorf("old password hash still present: %s", content)
	}
}

func TestActionResetAdminPasswordMismatch(t *testing.T) {
	input := "supersecret123\ndifferentsecret123\n\n"
	reader := bufio.NewReader(strings.NewReader(input))
	actionResetAdminPassword(reader)
}

func TestActionResetAdminPasswordShort(t *testing.T) {
	input := "short\n\n"
	reader := bufio.NewReader(strings.NewReader(input))
	actionResetAdminPassword(reader)
}

func batch5MtuAsFloat(t *testing.T, v interface{}) float64 {
	t.Helper()
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		t.Fatalf("unexpected MTU type %T (%v)", v, v)
		return 0
	}
}

func TestBatch5ResolveIfaceMtuPreservesExisting(t *testing.T) {
	// C27 regression: a stored jumbo MTU (9000, as JSON-decoded
	// float64) must survive a console interface rewrite; the old code
	// unconditionally wrote 1500.
	entry := map[string]interface{}{"name": "lan", "mtu": float64(9000)}
	if got := batch5MtuAsFloat(t, resolveIfaceMtu(entry)); got != 9000 {
		t.Errorf("expected existing MTU 9000 to be preserved, got %v", got)
	}
	// A stored MTU of 1500 stays 1500 (no spurious change).
	entry1500 := map[string]interface{}{"name": "wan", "mtu": float64(1500)}
	if got := batch5MtuAsFloat(t, resolveIfaceMtu(entry1500)); got != 1500 {
		t.Errorf("expected existing MTU 1500 to be preserved, got %v", got)
	}
}

func TestBatch5ResolveIfaceMtuDefaultsForNewEntries(t *testing.T) {
	// Brand-new entries (no mtu key at all) still default to 1500.
	if got := batch5MtuAsFloat(t, resolveIfaceMtu(map[string]interface{}{"name": "opt1"})); got != 1500 {
		t.Errorf("expected new-entry MTU default 1500, got %v", got)
	}
}

func TestGetAdminCredentialsDefaultFallback(t *testing.T) {
	// When running in test environment where /etc/axonwall/.password_changed does not exist,
	// getAdminCredentials should return adminUser "admin" and fallback adminPass "axonwall"
	u, p := getAdminCredentials()
	if u == "" {
		t.Errorf("expected non-empty adminUser, got empty string")
	}
	if p == "" {
		t.Errorf("expected non-empty adminPass fallback, got empty string")
	}
}
