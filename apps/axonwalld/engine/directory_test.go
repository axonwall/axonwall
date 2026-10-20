package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeriveBaseDN(t *testing.T) {
	tests := []struct {
		domain      string
		wantBaseDN  string
		wantFirstDC string
	}{
		{"", "dc=axonwall,dc=local", "axonwall"},
		{"local", "dc=axonwall,dc=local", "axonwall"},
		{"axonwall.local", "dc=axonwall,dc=local", "axonwall"},
		{"fw.corp.local", "dc=fw,dc=corp,dc=local", "fw"},
		{"EDGE.TEKROMANCY.IO.", "dc=edge,dc=tekromancy,dc=io", "edge"},
		{"singlelabel", "dc=singlelabel,dc=local", "singlelabel"},
	}

	for _, tc := range tests {
		gotDN, gotFirst := DeriveBaseDN(tc.domain)
		if gotDN != tc.wantBaseDN || gotFirst != tc.wantFirstDC {
			t.Errorf("DeriveBaseDN(%q) = (%q, %q), want (%q, %q)",
				tc.domain, gotDN, gotFirst, tc.wantBaseDN, tc.wantFirstDC)
		}
	}
}

func TestHashAndVerifySSHA(t *testing.T) {
	pw := "CorrectHorseBatteryStaple!99"
	hash, err := HashSSHA(pw)
	if err != nil {
		t.Fatalf("HashSSHA failed: %v", err)
	}
	if !strings.HasPrefix(hash, "{SSHA}") {
		t.Fatalf("expected {SSHA} prefix, got %q", hash)
	}
	if !VerifySSHA(pw, hash) {
		t.Errorf("VerifySSHA returned false for valid password")
	}
	if VerifySSHA("wrong-password", hash) {
		t.Errorf("VerifySSHA returned true for wrong password")
	}
}

func TestParseLDIFEntries(t *testing.T) {
	sample := `dn: uid=thoth,ou=users,dc=axonwall,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: ldapPublicKey
uid: thoth
cn: Thoth Admin
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/thoth
loginShell: /bin/bash
sshPublicKey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
 thoth@workstation

dn: uid=operator1,ou=users,dc=axonwall,dc=local
uid: operator1
cn:: T3BlcmF0b3IgT25l
uidNumber: 10011
gidNumber: 10011
loginShell: /usr/local/bin/axonwall-opshell
`
	entries := ParseLDIFEntries(sample)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if firstAttr(entries[0], "uid") != "thoth" {
		t.Errorf("expected uid=thoth, got %q", firstAttr(entries[0], "uid"))
	}
	// Verify LDIF line unfolding on sshPublicKey
	wantKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...thoth@workstation"
	if firstAttr(entries[0], "sshPublicKey") != wantKey {
		t.Errorf("unfolded sshPublicKey = %q, want %q", firstAttr(entries[0], "sshPublicKey"), wantKey)
	}
	// Verify base64 :: decoding on cn
	if firstAttr(entries[1], "cn") != "Operator One" {
		t.Errorf("decoded base64 cn = %q, want %q", firstAttr(entries[1], "cn"), "Operator One")
	}
}

func TestDefaultShellForRole(t *testing.T) {
	if DefaultShellForRole("admin") != "/bin/bash" {
		t.Errorf("expected /bin/bash for admin")
	}
	if DefaultShellForRole("operator") != "/usr/local/bin/axonwall-opshell" {
		t.Errorf("expected /usr/local/bin/axonwall-opshell for operator")
	}
	if DefaultShellForRole("readonly") != "/usr/sbin/nologin" {
		t.Errorf("expected /usr/sbin/nologin for readonly")
	}
}

func TestHAPKICertGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.crt")
	caKeyPath := filepath.Join(tmpDir, "ca.key")
	nodeCertPath := filepath.Join(tmpDir, "node.crt")
	nodeKeyPath := filepath.Join(tmpDir, "node.key")

	// Verify issueNodeCert works with an ephemeral CA
	err := EnsureHAPKICertsInDir(tmpDir, caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114")
	if err != nil {
		t.Fatalf("EnsureHAPKICertsInDir failed: %v", err)
	}
	if _, err := os.Stat(nodeCertPath); err != nil {
		t.Errorf("expected node.crt to exist: %v", err)
	}
}
