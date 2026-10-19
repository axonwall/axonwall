package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUserManagerParsingAndClassification(t *testing.T) {
	tmpDir := t.TempDir()
	passwdPath := filepath.Join(tmpDir, "passwd")
	groupPath := filepath.Join(tmpDir, "group")
	shadowPath := filepath.Join(tmpDir, "shadow")

	passwdContent := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
axonwall:x:998:998:Axonwall Daemon:/var/lib/axonwall:/bin/false
alice:x:1000:1000:Alice Admin,,,:/home/alice:/bin/bash
bob:x:1001:1001:Bob Operator,,,:/home/bob:/bin/bash
charlie:x:1002:1002:Charlie ReadOnly,,,:/home/charlie:/bin/sh
david:x:1003:1003:David OS Only,,,:/home/david:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`

	groupContent := `root:x:0:
daemon:x:1:
sudo:x:27:alice
axonwall:x:998:
axonwall-admin:x:1005:alice
axonwall-operator:x:1006:bob
axonwall-readonly:x:1007:charlie
customgroup:x:1008:david,bob
nogroup:x:65534:
`

	shadowContent := `root:$6$rounds=5000$salt$hash:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
axonwall:!:19000:0:99999:7:::
alice:$6$rounds=5000$salt$alicehash:19000:0:99999:7:::
bob:$6$rounds=5000$salt$bobhash:19000:0:99999:7:::
charlie:!:19000:0:99999:7:::
david:*:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
`

	if err := os.WriteFile(passwdPath, []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to write passwd: %v", err)
	}
	if err := os.WriteFile(groupPath, []byte(groupContent), 0644); err != nil {
		t.Fatalf("failed to write group: %v", err)
	}
	if err := os.WriteFile(shadowPath, []byte(shadowContent), 0640); err != nil {
		t.Fatalf("failed to write shadow: %v", err)
	}

	mgr := NewCustomUserManager(passwdPath, groupPath, shadowPath, nil)

	users, err := mgr.ParsePasswd()
	if err != nil {
		t.Fatalf("ParsePasswd failed: %v", err)
	}

	if len(users) != 9 {
		t.Fatalf("expected 9 users, got %d", len(users))
	}

	userMap := make(map[string]LocalUser)
	for _, u := range users {
		userMap[u.Username] = u
	}

	// 1. Root verification
	rootUser, ok := userMap["root"]
	if !ok {
		t.Fatal("root user not found")
	}
	if rootUser.IsSystem {
		t.Error("root should not be marked IsSystem=true (treated as human administrator)")
	}
	if !rootUser.Protected {
		t.Error("root must be marked Protected=true")
	}
	if rootUser.ApplianceRole != "admin" {
		t.Errorf("expected root ApplianceRole to be admin, got %s", rootUser.ApplianceRole)
	}

	// 2. System daemon verification (sshd, axonwall, nobody)
	axonwallUser, ok := userMap["axonwall"]
	if !ok || !axonwallUser.IsSystem || !axonwallUser.Protected {
		t.Errorf("axonwall daemon should be IsSystem=true and Protected=true: %+v", axonwallUser)
	}

	nobodyUser, ok := userMap["nobody"]
	if !ok || !nobodyUser.IsSystem || !nobodyUser.Protected {
		t.Errorf("nobody should be IsSystem=true and Protected=true: %+v", nobodyUser)
	}

	// 3. Human users verification
	// Alice (Admin)
	alice, ok := userMap["alice"]
	if !ok {
		t.Fatal("alice not found")
	}
	if alice.IsSystem || alice.Protected {
		t.Errorf("alice should be human non-protected: %+v", alice)
	}
	if alice.ApplianceRole != "admin" {
		t.Errorf("expected alice role=admin, got %s", alice.ApplianceRole)
	}
	if !alice.HasPassword || alice.PasswordLocked {
		t.Errorf("alice should have active password: %+v", alice)
	}

	// Bob (Operator)
	bob, ok := userMap["bob"]
	if !ok {
		t.Fatal("bob not found")
	}
	if bob.ApplianceRole != "operator" {
		t.Errorf("expected bob role=operator, got %s", bob.ApplianceRole)
	}

	// Charlie (ReadOnly)
	charlie, ok := userMap["charlie"]
	if !ok {
		t.Fatal("charlie not found")
	}
	if charlie.ApplianceRole != "readonly" {
		t.Errorf("expected charlie role=readonly, got %s", charlie.ApplianceRole)
	}
	if !charlie.PasswordLocked {
		t.Error("charlie password should be locked")
	}

	// David (OS Only)
	david, ok := userMap["david"]
	if !ok {
		t.Fatal("david not found")
	}
	if david.ApplianceRole != "os_only" {
		t.Errorf("expected david role=os_only, got %s", david.ApplianceRole)
	}

	// Test ParseGroups
	groups, err := mgr.ParseGroups()
	if err != nil {
		t.Fatalf("ParseGroups failed: %v", err)
	}
	if len(groups) != 9 {
		t.Fatalf("expected 9 groups, got %d", len(groups))
	}
}

func TestResolveApplianceRole(t *testing.T) {
	tests := []struct {
		username string
		groups   []string
		expected string
	}{
		{"root", []string{"root"}, "admin"},
		{"user1", []string{"axonwall-admin", "custom"}, "admin"},
		{"user2", []string{"sudo", "developers"}, "admin"},
		{"user3", []string{"wheel"}, "admin"},
		{"user4", []string{"axonwall-operator", "netops"}, "operator"},
		{"user5", []string{"axonwall-readonly"}, "readonly"},
		{"user6", []string{"docker", "dialout"}, "os_only"},
	}

	for _, tt := range tests {
		got := ResolveApplianceRole(tt.groups, tt.username)
		if got != tt.expected {
			t.Errorf("ResolveApplianceRole(%v, %s) = %s; want %s", tt.groups, tt.username, got, tt.expected)
		}
	}
}
