package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	wantAdmin := defaultInteractiveAdminShell()
	if DefaultShellForRole("admin") != wantAdmin {
		t.Errorf("expected %q for admin, got %q", wantAdmin, DefaultShellForRole("admin"))
	}
	if DefaultShellForRole("operator") != "/usr/local/bin/axonwall-opshell" {
		t.Errorf("expected /usr/local/bin/axonwall-opshell for operator")
	}
	if DefaultShellForRole("readonly") != "/usr/sbin/nologin" {
		t.Errorf("expected /usr/sbin/nologin for readonly")
	}
	if DefaultShellForRole("os_only") != wantAdmin {
		t.Errorf("expected %q for os_only, got %q", wantAdmin, DefaultShellForRole("os_only"))
	}

	// Verify Lean Core / Minimal fallback when zsh binaries are absent
	gotNoZsh := defaultInteractiveAdminShellWithStat(func(p string) bool { return p == "/bin/bash" })
	if gotNoZsh != "/bin/bash" {
		t.Errorf("expected /bin/bash fallback when zsh absent, got %q", gotNoZsh)
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

func TestDeriveSSSDBindPassword(t *testing.T) {
	repl := "deadbeef0123456789abcdef0123456789abcdef01234567"
	p1 := DeriveSSSDBindPassword(repl)
	p2 := DeriveSSSDBindPassword("  " + repl + "\n")
	if p1 != p2 {
		t.Fatalf("expected deterministic password across whitespace trim, got %q != %q", p1, p2)
	}
	if len(p1) != 64 {
		t.Fatalf("expected 64-char hex password, got len=%d (%q)", len(p1), p1)
	}
	for i := 0; i < len(p1); i++ {
		c := p1[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("expected lowercase hex character at index %d, got %q", i, c)
		}
	}
	if p1 == repl {
		t.Fatalf("derived SSSD bind password must differ from replication secret")
	}
}

func TestBuildSSSDConfigWithBind(t *testing.T) {
	withBind, err := BuildSSSDConfigWithBind("dc=axonwall,dc=local", "", "cn=svc-sssd,ou=services,dc=axonwall,dc=local", "secret123")
	if err != nil {
		t.Fatalf("loopback-only BuildSSSDConfigWithBind should not fail: %v", err)
	}
	for _, want := range []string{
		"shell_fallback = /bin/bash",
		"ldap_default_bind_dn = cn=svc-sssd,ou=services,dc=axonwall,dc=local",
		"ldap_default_authtok_type = password",
		"ldap_default_authtok = secret123",
	} {
		if !strings.Contains(withBind, want) {
			t.Fatalf("expected %q in SSSD config:\n%s", want, withBind)
		}
	}

	withoutBind, err := BuildSSSDConfigWithBind("dc=axonwall,dc=local", "", "", "")
	if err != nil {
		t.Fatalf("loopback-only bindless BuildSSSDConfigWithBind should not fail: %v", err)
	}
	for _, unwanted := range []string{
		"ldap_default_bind_dn",
		"ldap_default_authtok_type",
		"ldap_default_authtok",
	} {
		if strings.Contains(withoutBind, unwanted) {
			t.Fatalf("unexpected %q in bindless SSSD config:\n%s", unwanted, withoutBind)
		}
	}
}

func TestBuildSlapdBootstrapConfigLDIF_ACLs(t *testing.T) {
	ldif := BuildSlapdBootstrapConfigLDIF("dc=axonwall,dc=local", 1, "{SSHA}dummy")
	for _, want := range []string{
		`olcAccess: {0}to attrs=userPassword,shadowLastChange by self write by dn.regex=".*uidNumber=0,cn=peercred,cn=external,cn=auth$" manage by dn.exact="cn=replicator,dc=axonwall,dc=local" read by anonymous auth by * none`,
		`olcAccess: {1}to dn.subtree="ou=users,dc=axonwall,dc=local" attrs=entry,objectClass,ou,uid,sshPublicKey by dn.regex=".*uidNumber=0,cn=peercred,cn=external,cn=auth$" manage by dn.exact="cn=replicator,dc=axonwall,dc=local" read by users read by peername.ip="127.0.0.1" read by sockurl.regex="^ldapi://" read by * none`,
		`olcAccess: {2}to * by dn.regex=".*uidNumber=0,cn=peercred,cn=external,cn=auth$" manage by dn.exact="cn=replicator,dc=axonwall,dc=local" read by users read by * none`,
	} {
		if !strings.Contains(ldif, want) {
			t.Fatalf("missing expected ACL rule %q in LDIF:\n%s", want, ldif)
		}
	}
}

// R4-A-M1: an expired HA node leaf cert must be regenerated (normal
// path), and an expired CSR-enrolled leaf must fail loudly telling
// the operator to re-enroll (this node holds no CA key, so it cannot
// reissue). The old code only checked CA expiry, so a leaf past
// NotAfter was kept forever and mTLS broke permanently.
func TestHAPKIExpiredNodeCertRegenerated(t *testing.T) {
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
	// Replace the node cert with an expired leaf signed by the same CA.
	expireNodeCert := func(t *testing.T, caPath, caKeyPath, nodeCertPath, nodeKeyPath string) {
		t.Helper()
		caCertBytes, err := os.ReadFile(caPath)
		if err != nil {
			t.Fatal(err)
		}
		caBlock, _ := pem.Decode(caCertBytes)
		caCert, err := x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		caKeyBytes, err := os.ReadFile(caKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		caKeyBlock, _ := pem.Decode(caKeyBytes)
		caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "fw-01"},
			NotBefore:    time.Now().Add(-2 * time.Hour),
			NotAfter:     time.Now().Add(-1 * time.Hour),
			DNSNames:     []string{"fw-01"},
			IPAddresses:  []net.IP{net.ParseIP("10.80.0.113"), net.ParseIP("10.80.0.114")},
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &nodeKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(nodeCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(nodeKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(nodeKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	parseNodeCert := func(t *testing.T, nodeCertPath string) *x509.Certificate {
		t.Helper()
		b, err := os.ReadFile(nodeCertPath)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	t.Run("normal path regenerates expired leaf", func(t *testing.T) {
		dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath := setup(t)
		expireNodeCert(t, caPath, caKeyPath, nodeCertPath, nodeKeyPath)
		if got := parseNodeCert(t, nodeCertPath); !time.Now().After(got.NotAfter) {
			t.Fatalf("test setup: node cert should be expired, NotAfter=%s", got.NotAfter)
		}
		if err := EnsureHAPKICertsInDir(dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114"); err != nil {
			t.Fatalf("EnsureHAPKICertsInDir with expired leaf failed: %v", err)
		}
		if got := parseNodeCert(t, nodeCertPath); time.Now().After(got.NotAfter) {
			t.Fatalf("expired node cert was not regenerated, NotAfter=%s", got.NotAfter)
		}
	})

	t.Run("CSR-enrolled expired leaf fails loudly", func(t *testing.T) {
		dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath := setup(t)
		expireNodeCert(t, caPath, caKeyPath, nodeCertPath, nodeKeyPath)
		// Simulate CSR enrollment: CA cert without the CA key.
		if err := os.Remove(caKeyPath); err != nil {
			t.Fatal(err)
		}
		err := EnsureHAPKICertsInDir(dir, caPath, caKeyPath, nodeCertPath, nodeKeyPath, "fw-01", "10.80.0.113", "10.80.0.114")
		if err == nil {
			t.Fatal("expected an error for an expired CSR-enrolled node cert, got nil")
		}
		if !strings.Contains(err.Error(), "re-enroll") {
			t.Fatalf("expected the error to direct the operator to re-enroll, got: %v", err)
		}
	})
}

func TestDirectoryNSSMirrorBlocksPrivilegedAndLowGIDGroups(t *testing.T) {
	tmp := t.TempDir()
	prevPasswd, prevGroup, prevShadow, prevState := etcPasswdPath, etcGroupPath, etcShadowPath, mirroredNSSStatePath
	etcPasswdPath = filepath.Join(tmp, "passwd")
	etcGroupPath = filepath.Join(tmp, "group")
	etcShadowPath = filepath.Join(tmp, "shadow")
	mirroredNSSStatePath = filepath.Join(tmp, "mirrored-nss.json")
	t.Cleanup(func() {
		etcPasswdPath = prevPasswd
		etcGroupPath = prevGroup
		etcShadowPath = prevShadow
		mirroredNSSStatePath = prevState
	})

	_ = os.WriteFile(etcPasswdPath, []byte("root:x:0:0:root:/root:/bin/bash\naxonwall-api:x:999:999::/var/lib/axonwall:/bin/false\n"), 0644)
	_ = os.WriteFile(etcGroupPath, []byte(
		"root:x:0:\n"+
			"sudo:x:27:localadmin\n"+
			"shadow:x:42:\n"+
			"axonwall-api:x:999:\n"+
			"lowgidlocal:x:500:\n",
	), 0644)
	_ = os.WriteFile(etcShadowPath, []byte("root:*:19723:0:99999:7:::\n"), 0640)

	dm := &DirectoryManager{}
	dm.applyLocalNSSMirror("",
		[]LocalUser{
			{Username: "mallory", UID: 10050, GID: 10050, Comment: "Mallory", HomeDir: "/home/mallory", Shell: "/bin/bash"},
			{Username: "axonwall-api", UID: 10051, GID: 10051, Comment: "Spoof", HomeDir: "/tmp", Shell: "/bin/bash"},
		},
		[]LocalGroup{
			{Name: "root", GID: 10050, Members: []string{"mallory"}},
			{Name: "sudo", GID: 10051, Members: []string{"mallory"}},
			{Name: "shadow", GID: 10052, Members: []string{"mallory"}},
			{Name: "axonwall-api", GID: 10053, Members: []string{"mallory"}},
			{Name: "lowgidlocal", GID: 10054, Members: []string{"mallory"}},
			{Name: "wheel", GID: 10055, Members: []string{"mallory"}},
			{Name: "evilpriv", GID: 501, Members: []string{"mallory"}},
			{Name: "netops", GID: 10060, Members: []string{"mallory"}},
		},
	)

	grBytes, err := os.ReadFile(etcGroupPath)
	if err != nil {
		t.Fatal(err)
	}
	gr := string(grBytes)
	for _, protectedLine := range []string{
		"root:x:0:",
		"sudo:x:27:localadmin",
		"shadow:x:42:",
		"axonwall-api:x:999:",
		"lowgidlocal:x:500:",
	} {
		if !strings.Contains(gr, protectedLine+"\n") {
			t.Fatalf("expected protected local group line %q to remain unmodified:\n%s", protectedLine, gr)
		}
	}
	if strings.Contains(gr, "wheel:") || strings.Contains(gr, "evilpriv:") {
		t.Fatalf("expected privileged/low-GID LDAP groups not to be added:\n%s", gr)
	}
	if !strings.Contains(gr, "netops:x:10060:mallory\n") {
		t.Fatalf("expected legitimate LDAP group netops to be mirrored:\n%s", gr)
	}

	pwBytes, err := os.ReadFile(etcPasswdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pwBytes), "axonwall-api:x:999:999::/var/lib/axonwall:/bin/false") {
		t.Fatalf("expected system user axonwall-api to remain unmodified:\n%s", string(pwBytes))
	}
}
