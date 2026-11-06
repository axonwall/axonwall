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
	if DefaultShellForRole("admin") != "/usr/bin/zsh" {
		t.Errorf("expected /usr/bin/zsh for admin")
	}
	if DefaultShellForRole("operator") != "/usr/local/bin/axonwall-opshell" {
		t.Errorf("expected /usr/local/bin/axonwall-opshell for operator")
	}
	if DefaultShellForRole("readonly") != "/usr/sbin/nologin" {
		t.Errorf("expected /usr/sbin/nologin for readonly")
	}
	if DefaultShellForRole("os_only") != "/usr/bin/zsh" {
		t.Errorf("expected /usr/bin/zsh for os_only")
	}
}

func TestBuildSlapdSeedDITLDIF_ContainsServicesOU(t *testing.T) {
	dit := BuildSlapdSeedDITLDIF("dc=axonwall,dc=local", "axonwall", "{SSHA}test", DefaultPasswordPolicyConfig())
	if !strings.Contains(dit, "dn: ou=services,dc=axonwall,dc=local") {
		t.Errorf("BuildSlapdSeedDITLDIF missing ou=services definition")
	}
	if !strings.Contains(dit, "ou: services") {
		t.Errorf("BuildSlapdSeedDITLDIF missing ou: services attribute")
	}
	if !strings.Contains(dit, "dn: cn=axonwall-admin,ou=groups,dc=axonwall,dc=local") {
		t.Errorf("BuildSlapdSeedDITLDIF missing axonwall-admin group")
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

func TestHAPKICorruptCAMaterialRefusesToReRoot(t *testing.T) {
	// A-H4 (round 2): a corrupt CA cert/key, or a CSR-enrolled node
	// missing its key, used to silently mint a brand-new CA and
	// overwrite the old one — orphaning every peer cert in the cluster.
	setup := func(t *testing.T) (dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath string) {
		t.Helper()
		dir = t.TempDir()
		caPath = filepath.Join(dir, "ca.crt")
		caKeyPath = filepath.Join(dir, "ca.key")
		nodeCertPath = filepath.Join(dir, "node.crt")
		nodeKeyPath = filepath.Join(dir, "node.key")
		if err := EnsureHAPKICertsInDir(dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114"); err != nil {
			t.Fatalf("setup EnsureHAPKICertsInDir failed: %v", err)
		}
		return dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath
	}

	t.Run("corrupt CA cert", func(t *testing.T) {
		_, caPath, caKeyPath, nodeCertPath, nodeKeyPath := setup(t)
		corrupt := []byte("-----BEGIN CERTIFICATE-----\ncorrupt\n-----END CERTIFICATE-----\n")
		if err := os.WriteFile(caPath, corrupt, 0644); err != nil {
			t.Fatalf("failed to corrupt ca.crt: %v", err)
		}
		if err := EnsureHAPKICertsInDir(filepath.Dir(caPath), caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114"); err == nil {
			t.Fatalf("expected error for corrupt CA certificate, got nil")
		}
		after, _ := os.ReadFile(caPath)
		if string(after) != string(corrupt) {
			t.Fatalf("corrupt CA certificate was overwritten instead of refused")
		}
	})

	t.Run("corrupt CA key", func(t *testing.T) {
		_, caPath, caKeyPath, nodeCertPath, nodeKeyPath := setup(t)
		if err := os.WriteFile(caKeyPath, []byte("not a pem key"), 0600); err != nil {
			t.Fatalf("failed to corrupt ca.key: %v", err)
		}
		if err := EnsureHAPKICertsInDir(filepath.Dir(caPath), caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114"); err == nil {
			t.Fatalf("expected error for corrupt CA key, got nil")
		}
	})

	t.Run("CA key without certificate", func(t *testing.T) {
		_, caPath, caKeyPath, nodeCertPath, nodeKeyPath := setup(t)
		if err := os.Remove(caPath); err != nil {
			t.Fatalf("failed to remove ca.crt: %v", err)
		}
		if err := EnsureHAPKICertsInDir(filepath.Dir(caPath), caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114"); err == nil {
			t.Fatalf("expected error for CA key without certificate, got nil")
		}
	})

	t.Run("CSR-enrolled node keeps working, missing node key fails", func(t *testing.T) {
		dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath := setup(t)
		// Simulate CSR enrollment: CA cert without the CA key.
		if err := os.Remove(caKeyPath); err != nil {
			t.Fatalf("failed to remove ca.key: %v", err)
		}
		if err := EnsureHAPKICertsInDir(dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114"); err != nil {
			t.Fatalf("CSR-enrolled node with intact key/cert should be preserved, got: %v", err)
		}
		// Now lose the node key: must fail, not mint a new CA.
		if err := os.Remove(nodeKeyPath); err != nil {
			t.Fatalf("failed to remove node.key: %v", err)
		}
		if err := EnsureHAPKICertsInDir(dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114"); err == nil {
			t.Fatalf("expected error for CSR-enrolled node missing its key, got nil")
		}
	})
}

func TestLDAPDeleteEntry(t *testing.T) {
	// A-H5 (round 2): DeleteUser discarded both ldapdelete errors and
	// reported success while the user still existed.
	installFakeLDAPDelete := func(t *testing.T, script string) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "ldapdelete"), []byte(script), 0755); err != nil {
			t.Fatalf("Failed to write fake ldapdelete: %v", err)
		}
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	}

	t.Run("success", func(t *testing.T) {
		installFakeLDAPDelete(t, "#!/bin/sh\nexit 0\n")
		if err := ldapDeleteEntry("uid=test,ou=users,dc=example,dc=com"); err != nil {
			t.Errorf("expected nil for successful delete, got %v", err)
		}
	})

	t.Run("no such object is tolerated", func(t *testing.T) {
		installFakeLDAPDelete(t, "#!/bin/sh\necho 'ldap_delete: No such object' >&2\nexit 32\n")
		if err := ldapDeleteEntry("uid=test,ou=users,dc=example,dc=com"); err != nil {
			t.Errorf("expected nil for missing entry, got %v", err)
		}
	})

	t.Run("other failures are errors", func(t *testing.T) {
		installFakeLDAPDelete(t, "#!/bin/sh\necho 'ldap_sasl_bind: connection refused' >&2\nexit 1\n")
		if err := ldapDeleteEntry("uid=test,ou=users,dc=example,dc=com"); err == nil {
			t.Errorf("expected error when ldapdelete fails, got nil")
		}
	})
}

func TestRunLDAPModifyAddFallback(t *testing.T) {
	// A-H6 (round 2): every ldapmodify failure containing "No such
	// attribute" was treated as success — but replace: in LDAP requires
	// the attribute to exist, so a first-time lock and a first SSH key
	// were silently dropped. Only delete: may swallow it; replace: on
	// pwdAccountLockedTime / sshPublicKey must retry as add:.
	installFakeLDAPModify := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		logPath := filepath.Join(dir, "ldapmodify.log")
		script := "#!/bin/sh\n" +
			"body=$(cat)\n" +
			"printf '%s\\n---CALL---\\n' \"$body\" >> \"$LDAPMODIFY_LOG\"\n" +
			"case \"$body\" in\n" +
			"  *\"replace: sshPublicKey\"*|*\"replace: pwdAccountLockedTime\"*|*\"replace: gecos\"*|*\"delete: pwdAccountLockedTime\"*)\n" +
			"    echo 'ldap_modify: No such attribute' >&2\n" +
			"    exit 1\n" +
			"    ;;\n" +
			"esac\n" +
			"exit 0\n"
		if err := os.WriteFile(filepath.Join(dir, "ldapmodify"), []byte(script), 0755); err != nil {
			t.Fatalf("Failed to write fake ldapmodify: %v", err)
		}
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
		t.Setenv("LDAPMODIFY_LOG", logPath)
		return logPath
	}
	readLog := func(t *testing.T, p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("Failed to read ldapmodify log: %v", err)
		}
		return string(b)
	}
	d := &DirectoryManager{}

	t.Run("first lock retries as add", func(t *testing.T) {
		logPath := installFakeLDAPModify(t)
		err := d.runLDAPModify("alice", "dc=example,dc=com", "replace: pwdAccountLockedTime\npwdAccountLockedTime: 000001010000Z")
		if err != nil {
			t.Fatalf("expected first lock to succeed via add: retry, got %v", err)
		}
		log := readLog(t, logPath)
		if !strings.Contains(log, "replace: pwdAccountLockedTime") || !strings.Contains(log, "add: pwdAccountLockedTime") {
			t.Fatalf("expected a replace attempt followed by an add attempt, got log:\n%s", log)
		}
	})

	t.Run("first ssh key retries as add", func(t *testing.T) {
		logPath := installFakeLDAPModify(t)
		err := d.runLDAPModify("alice", "dc=example,dc=com", "replace: sshPublicKey\nsshPublicKey: ssh-ed25519 AAAAC3test")
		if err != nil {
			t.Fatalf("expected first SSH key to succeed via add: retry, got %v", err)
		}
		if log := readLog(t, logPath); !strings.Contains(log, "add: sshPublicKey") {
			t.Fatalf("expected an add: retry for the first SSH key, got log:\n%s", log)
		}
	})

	t.Run("unlock of never-locked user is a no-op success", func(t *testing.T) {
		logPath := installFakeLDAPModify(t)
		err := d.runLDAPModify("alice", "dc=example,dc=com", "delete: pwdAccountLockedTime")
		if err != nil {
			t.Fatalf("expected delete of absent attribute to succeed, got %v", err)
		}
		if log := readLog(t, logPath); strings.Count(log, "---CALL---") != 1 {
			t.Fatalf("expected exactly one ldapmodify call for a delete, got log:\n%s", log)
		}
	})

	t.Run("bare replace of absent attribute is a no-op success", func(t *testing.T) {
		logPath := installFakeLDAPModify(t)
		err := d.runLDAPModify("alice", "dc=example,dc=com", "replace: sshPublicKey")
		if err != nil {
			t.Fatalf("expected bare replace of absent sshPublicKey to succeed, got %v", err)
		}
		if log := readLog(t, logPath); strings.Count(log, "---CALL---") != 1 {
			t.Fatalf("expected exactly one ldapmodify call for a bare replace, got log:\n%s", log)
		}
	})

	t.Run("other replace failures are real errors", func(t *testing.T) {
		installFakeLDAPModify(t)
		err := d.runLDAPModify("alice", "dc=example,dc=com", "replace: gecos\ngecos: Alice")
		if err == nil {
			t.Fatalf("expected error for a failing replace: gecos, got nil")
		}
	})
}

func TestVowPluginLDAPIntegrationSpec(t *testing.T) {
	plugins := GetExtensionPluginDefinitions()
	var vowFound bool
	for _, p := range plugins {
		if p.ID == "vigilant-octo-waffle" {
			vowFound = true
			if p.LdapIntegration == nil {
				t.Fatalf("expected vigilant-octo-waffle to have LdapIntegration")
			}
			if p.LdapIntegration.ServiceAccountCN != "svc-vow" {
				t.Errorf("expected ServiceAccountCN=svc-vow, got %q", p.LdapIntegration.ServiceAccountCN)
			}
			if p.LdapIntegration.EnvPrefix != "VOW_LDAP_" {
				t.Errorf("expected EnvPrefix=VOW_LDAP_, got %q", p.LdapIntegration.EnvPrefix)
			}
			if len(p.LdapIntegration.Groups) != 3 {
				t.Fatalf("expected 3 LDAP groups on vigilant-octo-waffle, got %d", len(p.LdapIntegration.Groups))
			}
		}
	}
	if !vowFound {
		t.Fatalf("vigilant-octo-waffle plugin not found in catalog")
	}
}

func TestCoreVigilantePluginLDAPIntegrationSpec(t *testing.T) {
	spec := GetCoreVigilanteLDAPSpec()
	if spec.ServiceAccountCN != "svc-vigilante" {
		t.Errorf("expected ServiceAccountCN=svc-vigilante, got %q", spec.ServiceAccountCN)
	}
	if spec.EnvPrefix != "VIGILANTE_LDAP_" {
		t.Errorf("expected EnvPrefix=VIGILANTE_LDAP_, got %q", spec.EnvPrefix)
	}
	if !spec.InheritApplianceRoleGroups {
		t.Errorf("expected InheritApplianceRoleGroups=true on core-vigilante")
	}
	if len(spec.Groups) != 3 {
		t.Fatalf("expected 3 LDAP groups on core-vigilante, got %d", len(spec.Groups))
	}
	wantGroups := map[string]int{
		"vigilante-admin":    10230,
		"vigilante-operator": 10231,
		"vigilante-readonly": 10232,
	}
	for _, g := range spec.Groups {
		if wantGID, ok := wantGroups[g.CN]; !ok || g.GIDNumber != wantGID {
			t.Errorf("unexpected LDAP group %+v", g)
		}
	}
}

