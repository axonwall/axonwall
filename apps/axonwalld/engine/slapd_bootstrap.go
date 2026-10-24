package engine

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	LDAPBaseDir       = "/var/lib/axonwall/ldap"
	LDAPConfigDir     = "/var/lib/axonwall/ldap/config"
	LDAPDataDir       = "/var/lib/axonwall/ldap/data"
	LDAPAccessLogDir  = "/var/lib/axonwall/ldap/accesslog"
	LDAPBackupsDir    = "/var/lib/axonwall/ldap/backups"
	LDAPBaseDNFile    = "/var/lib/axonwall/ldap/BASE_DN"
	LDAPSecretsDir    = "/var/lib/axonwall/secrets/ldap"
	LDAPAdminPassFile = "/var/lib/axonwall/secrets/ldap/admin.pw"
	LDAPReplPassFile  = "/var/lib/axonwall/secrets/ldap/repl.pw"
)

var validDomainLabelRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// DeriveBaseDN converts an appliance domain (e.g. "fw.corp.local" or "local")
// into a standard RFC 2247 LDAP Base DN (e.g. "dc=fw,dc=corp,dc=local") and its top-level dc value.
func DeriveBaseDN(domain string) (string, string) {
	cleaned := strings.ToLower(strings.TrimSpace(domain))
	cleaned = strings.Trim(cleaned, ".")
	if cleaned == "" || cleaned == "local" || cleaned == "localhost" {
		cleaned = "axonwall.local"
	}

	rawParts := strings.Split(cleaned, ".")
	var labels []string
	for _, p := range rawParts {
		p = strings.TrimSpace(p)
		if validDomainLabelRegex.MatchString(p) {
			labels = append(labels, p)
		}
	}

	if len(labels) == 0 {
		labels = []string{"axonwall", "local"}
	} else if len(labels) == 1 {
		labels = append(labels, "local")
	}

	var dcs []string
	for _, l := range labels {
		dcs = append(dcs, "dc="+l)
	}
	return strings.Join(dcs, ","), labels[0]
}

// HashSSHA generates an OpenLDAP-compatible {SSHA} password digest in pure Go
// without spawning external processes or exposing secrets via argv.
func HashSSHA(password string) (string, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	h := sha1.New()
	h.Write([]byte(password))
	h.Write(salt)
	digest := append(h.Sum(nil), salt...)
	return "{SSHA}" + base64.StdEncoding.EncodeToString(digest), nil
}

// VerifySSHA verifies a plaintext password against an OpenLDAP {SSHA} hash in pure Go.
func VerifySSHA(password, sshaHash string) bool {
	if !strings.HasPrefix(sshaHash, "{SSHA}") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sshaHash, "{SSHA}"))
	if err != nil || len(raw) <= sha1.Size {
		return false
	}
	digest := raw[:sha1.Size]
	salt := raw[sha1.Size:]
	h := sha1.New()
	h.Write([]byte(password))
	h.Write(salt)
	return bytes.Equal(h.Sum(nil), digest)
}

func ensureRandomSecretFile(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(data))
		if len(s) >= 16 {
			return s, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(secret+"\n"), 0600); err != nil {
		return "", err
	}
	return secret, nil
}

// resolveSlapdUserGroup detects the OS service account for OpenLDAP ("openldap" on Debian, "ldap" on Alpine).
func resolveSlapdUserGroup() (string, string) {
	if _, err := user.Lookup("openldap"); err == nil {
		return "openldap", "openldap"
	}
	if _, err := user.Lookup("ldap"); err == nil {
		return "ldap", "ldap"
	}
	return "openldap", "openldap"
}

func chownOpenLDAPRecursive(path string) {
	uName, _ := resolveSlapdUserGroup()
	u, err := user.Lookup(uName)
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			_ = os.Chown(p, uid, gid)
		}
		return nil
	})
}

// ConfigureSlapdSystemPaths writes /etc/default/slapd (Debian), /etc/conf.d/slapd (Alpine OpenRC),
// cross-distro schema/module symlinks, and AppArmor overrides so slapd uses /var/lib/axonwall/ldap/config.
func ConfigureSlapdSystemPaths() error {
	slapdUser, slapdGroup := resolveSlapdUserGroup()

	// Ensure cross-distro schema & module symlinks exist so cn=config works identically on Debian and Alpine
	if _, err := os.Stat("/etc/openldap/schema"); err == nil {
		if _, err := os.Stat("/etc/ldap"); os.IsNotExist(err) {
			_ = os.Symlink("/etc/openldap", "/etc/ldap")
		} else if _, err := os.Stat("/etc/ldap/schema"); os.IsNotExist(err) {
			_ = os.Symlink("/etc/openldap/schema", "/etc/ldap/schema")
		}
	}
	if _, err := os.Stat("/usr/lib/openldap"); err == nil {
		if _, err := os.Stat("/usr/lib/ldap"); os.IsNotExist(err) {
			_ = os.Symlink("/usr/lib/openldap", "/usr/lib/ldap")
		}
	}

	// Ensure runtime socket directories exist for both Debian (/run/slapd) and Alpine (/var/lib/openldap/run, /run/openldap)
	for _, rdir := range []string{"/run/slapd", "/run/openldap", "/var/lib/openldap/run"} {
		_ = os.MkdirAll(rdir, 0755)
		chownOpenLDAPRecursive(rdir)
	}

	_ = os.MkdirAll("/etc/default", 0755)
	slapdDefault := fmt.Sprintf(`# Managed by Axonwall Identity Engine
SLAPD_CONF="/var/lib/axonwall/ldap/config"
SLAPD_USER="%s"
SLAPD_GROUP="%s"
SLAPD_PIDFILE="/run/slapd/slapd.pid"
SLAPD_SERVICES="ldap://127.0.0.1:389/ ldaps:/// ldapi:///"
SLAPD_SENTINEL_FILE=/etc/ldap/noslapd
SLAPD_OPTIONS=""
`, slapdUser, slapdGroup)
	if err := os.WriteFile("/etc/default/slapd", []byte(slapdDefault), 0644); err != nil {
		return fmt.Errorf("failed to write /etc/default/slapd: %w", err)
	}

	// Alpine OpenRC configuration (/etc/conf.d/slapd)
	if _, err := os.Stat("/etc/conf.d"); err == nil {
		slapdConfD := `# Managed by Axonwall Identity Engine
cfgfile=""
cfgdir="/var/lib/axonwall/ldap/config"
listen_uris="ldap://127.0.0.1:389/ ldaps:/// ldapi:///"
`
		_ = os.WriteFile("/etc/conf.d/slapd", []byte(slapdConfD), 0644)
	}

	// Ensure AppArmor permits slapd to access /var/lib/axonwall/ldap/** and /var/lib/axonwall/secrets/ha-pki/**
	if _, err := os.Stat("/etc/apparmor.d"); err == nil {
		_ = os.MkdirAll("/etc/apparmor.d/local", 0755)
		aaLocal := `# Managed by Axonwall Identity Engine
/var/lib/axonwall/ldap/ r,
/var/lib/axonwall/ldap/** rwk,
/var/lib/axonwall/secrets/ha-pki/ r,
/var/lib/axonwall/secrets/ha-pki/** r,
`
		aaPath := "/etc/apparmor.d/local/usr.sbin.slapd"
		existing, _ := os.ReadFile(aaPath)
		if string(existing) != aaLocal {
			_ = os.WriteFile(aaPath, []byte(aaLocal), 0644)
			if parser, err := exec.LookPath("apparmor_parser"); err == nil {
				if _, err := os.Stat("/etc/apparmor.d/usr.sbin.slapd"); err == nil {
					_ = exec.Command(parser, "-r", "/etc/apparmor.d/usr.sbin.slapd").Run()
				}
			}
		}
	}

	return nil
}

// BuildSlapdBootstrapConfigLDIF generates the initial cn=config LDIF for slapadd -n 0.
func BuildSlapdBootstrapConfigLDIF(baseDN string, serverID int, adminHash string) string {
	if serverID < 1 {
		serverID = 1
	}
	return fmt.Sprintf(`dn: cn=config
objectClass: olcGlobal
cn: config
olcArgsFile: /run/slapd/slapd.args
olcPidFile: /run/slapd/slapd.pid
olcServerID: %d
olcToolThreads: 2
olcLogLevel: stats sync

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
olcModuleLoad: {0}back_mdb
olcModuleLoad: {1}syncprov
olcModuleLoad: {2}ppolicy
olcModuleLoad: {3}unique
olcModuleLoad: {4}accesslog

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/ldap/schema/core.ldif
include: file:///etc/ldap/schema/cosine.ldif
include: file:///etc/ldap/schema/nis.ldif
include: file:///etc/ldap/schema/inetorgperson.ldif

dn: cn=openssh-lpk,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: openssh-lpk
olcAttributeTypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey' DESC 'MANDATORY: OpenSSH Public key' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcObjectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' DESC 'MANDATORY: OpenSSH LPK objectclass' SUP top AUXILIARY MAY ( sshPublicKey $ uid ) )

dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend
olcAccess: {0}to * by dn.regex=".*uidNumber=0,cn=peercred,cn=external,cn=auth$" manage by * break
olcAccess: {1}to dn.exact="" by * read
olcAccess: {2}to dn.base="cn=Subschema" by * read

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcAccess: {0}to * by dn.regex=".*uidNumber=0,cn=peercred,cn=external,cn=auth$" manage by * none

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcDbDirectory: %s
olcSuffix: %s
olcRootDN: cn=admin,%s
olcRootPW: %s
olcDbMaxSize: 536870912
olcDbIndex: objectClass eq
olcDbIndex: uid,cn eq,sub
olcDbIndex: uidNumber,gidNumber eq
olcDbIndex: member,memberUid eq
olcDbIndex: entryCSN,entryUUID eq
olcAccess: {0}to attrs=userPassword,shadowLastChange by self write by dn.regex=".*uidNumber=0,cn=peercred,cn=external,cn=auth$" manage by dn.exact="cn=replicator,%s" read by anonymous auth by * none
olcAccess: {1}to * by dn.regex=".*uidNumber=0,cn=peercred,cn=external,cn=auth$" manage by dn.exact="cn=replicator,%s" read by users read by anonymous read

dn: olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcSyncProvConfig
olcOverlay: {0}syncprov
olcSpCheckpoint: 100 10
olcSpSessionlog: 1000

dn: olcOverlay={1}unique,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcUniqueConfig
olcOverlay: {1}unique
olcUniqueURI: ldap:///?uid?sub
olcUniqueURI: ldap:///?uidNumber?sub

dn: olcOverlay={2}ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: {2}ppolicy
olcPPolicyDefault: cn=default,ou=policies,%s
olcPPolicyHashCleartext: TRUE
olcPPolicyUseLockout: TRUE
`, serverID, LDAPDataDir, baseDN, baseDN, adminHash, baseDN, baseDN, baseDN)
}

// BuildSlapdSeedDITLDIF generates the initial base tree LDIF (organizational units,
// replicator service account, default password policy, and default POSIX groups).
func BuildSlapdSeedDITLDIF(baseDN, firstDC, replHash string, policy PasswordPolicyConfig) string {
	maxAgeSeconds := policy.MaxAgeDays * 86400
	return fmt.Sprintf(`dn: %s
objectClass: top
objectClass: dcObject
objectClass: organization
o: Axonwall Appliance Identity Directory
dc: %s

dn: ou=users,%s
objectClass: top
objectClass: organizationalUnit
ou: users

dn: ou=groups,%s
objectClass: top
objectClass: organizationalUnit
ou: groups

dn: ou=policies,%s
objectClass: top
objectClass: organizationalUnit
ou: policies

dn: ou=sudoers,%s
objectClass: top
objectClass: organizationalUnit
ou: sudoers

dn: cn=replicator,%s
objectClass: top
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: replicator
description: Axonwall HA Multi-Provider Replication Account
userPassword: %s

dn: cn=default,ou=policies,%s
objectClass: top
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: userPassword
pwdMinLength: %d
pwdInHistory: %d
pwdMaxFailure: %d
pwdLockout: TRUE
pwdLockoutDuration: %d
pwdFailureCountInterval: 300
pwdMaxAge: %d
pwdAllowUserChange: TRUE
pwdSafeModify: FALSE

dn: cn=axonwall-admin,ou=groups,%s
objectClass: top
objectClass: posixGroup
cn: axonwall-admin
gidNumber: 10000
description: Axonwall Full Administrators

dn: cn=axonwall-operator,ou=groups,%s
objectClass: top
objectClass: posixGroup
cn: axonwall-operator
gidNumber: 10001
description: Axonwall Restricted Operators

dn: cn=axonwall-readonly,ou=groups,%s
objectClass: top
objectClass: posixGroup
cn: axonwall-readonly
gidNumber: 10002
description: Axonwall Read-Only Auditors

dn: cn=sudo,ou=groups,%s
objectClass: top
objectClass: posixGroup
cn: sudo
gidNumber: 10003
description: Linux Sudoers Group

dn: cn=adm,ou=groups,%s
objectClass: top
objectClass: posixGroup
cn: adm
gidNumber: 10004
description: System Monitoring Logs Group
`, baseDN, firstDC, baseDN, baseDN, baseDN, baseDN, baseDN, replHash, baseDN,
		policy.MinLength, policy.HistoryCount, policy.MaxFailures, policy.LockoutDurationSeconds, maxAgeSeconds,
		baseDN, baseDN, baseDN, baseDN, baseDN)
}

// ResolveOrCreateBaseDN returns the persisted Base DN from /var/lib/axonwall/ldap/BASE_DN,
// or derives and persists it from domain if not yet bootstrapped.
func ResolveOrCreateBaseDN(domain string) (string, string, error) {
	if data, err := os.ReadFile(LDAPBaseDNFile); err == nil {
		persisted := strings.TrimSpace(string(data))
		if persisted != "" && strings.HasPrefix(persisted, "dc=") {
			firstPart := strings.Split(persisted, ",")[0]
			firstDC := strings.TrimPrefix(firstPart, "dc=")
			return persisted, firstDC, nil
		}
	}
	baseDN, firstDC := DeriveBaseDN(domain)
	if err := os.MkdirAll(LDAPBaseDir, 0750); err != nil {
		return baseDN, firstDC, err
	}
	_ = os.WriteFile(LDAPBaseDNFile, []byte(baseDN+"\n"), 0644)
	return baseDN, firstDC, nil
}

// EnsureOpenLDAPBootstrapped ensures OpenLDAP is configured on the shared /var/lib/axonwall/ldap
// partition, starts slapd, and seeds the base DIT if needed.
func EnsureOpenLDAPBootstrapped(domain string, serverID int, policy PasswordPolicyConfig) (string, error) {
	if _, err := exec.LookPath("slapd"); err != nil {
		return "", fmt.Errorf("slapd binary not installed: %w", err)
	}

	// Ensure /var/lib/axonwall is traversable by openldap and SSSD/SSH users
	_ = os.Chmod("/var/lib/axonwall", 0755)
	for _, dir := range []string{LDAPBaseDir, LDAPConfigDir, LDAPDataDir, LDAPAccessLogDir, LDAPBackupsDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return "", fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}
	if err := os.MkdirAll(LDAPSecretsDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create %s: %w", LDAPSecretsDir, err)
	}

	baseDN, firstDC, err := ResolveOrCreateBaseDN(domain)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base DN: %w", err)
	}

	adminPass, err := ensureRandomSecretFile(LDAPAdminPassFile)
	if err != nil {
		return "", fmt.Errorf("failed to initialize LDAP admin password: %w", err)
	}
	replPass, err := ensureRandomSecretFile(LDAPReplPassFile)
	if err != nil {
		return "", fmt.Errorf("failed to initialize LDAP replicator password: %w", err)
	}

	if err := ConfigureSlapdSystemPaths(); err != nil {
		log.Printf("[Directory] Warning configuring slapd system paths: %v", err)
	}

	configMarker := filepath.Join(LDAPConfigDir, "cn=config.ldif")
	needConfigBootstrap := false
	if _, err := os.Stat(configMarker); os.IsNotExist(err) {
		needConfigBootstrap = true
	}

	if needConfigBootstrap {
		log.Printf("[Directory] Bootstrapping OpenLDAP cn=config in %s (baseDN=%s, serverID=%d)...", LDAPConfigDir, baseDN, serverID)
		_ = exec.Command("systemctl", "stop", "slapd").Run()

		adminHash, err := HashSSHA(adminPass)
		if err != nil {
			return "", err
		}

		configLDIF := BuildSlapdBootstrapConfigLDIF(baseDN, serverID, adminHash)
		cmd := exec.Command("slapadd", "-n", "0", "-F", LDAPConfigDir)
		cmd.Stdin = strings.NewReader(configLDIF)
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("slapadd -n 0 failed: %s (%w)", string(out), err)
		}
	}

	chownOpenLDAPRecursive(LDAPBaseDir)
	// Ownership without mode is not enough: re-assert 0750 on the ldap
	// directories so slapd (running as the unprivileged slapd user) can
	// always read its own config tree, even on images whose shipped
	// directory modes were looser or tighter than intended.
	for _, dir := range []string{LDAPBaseDir, LDAPConfigDir, LDAPDataDir, LDAPAccessLogDir, LDAPBackupsDir} {
		_ = os.Chmod(dir, 0750)
	}
	for _, rdir := range []string{"/run/slapd", "/run/openldap", "/var/lib/openldap/run"} {
		_ = os.MkdirAll(rdir, 0755)
		chownOpenLDAPRecursive(rdir)
	}

	// Ensure slapd is enabled and running
	_ = exec.Command("systemctl", "enable", "slapd").Run()
	if exec.Command("ldapsearch", "-LLL", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", "cn=config", "-s", "base", "dn").Run() != nil {
		out, err := exec.Command("systemctl", "restart", "slapd").CombinedOutput()
		time.Sleep(200 * time.Millisecond)
		if err != nil || exec.Command("ldapsearch", "-LLL", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", "cn=config", "-s", "base", "dn").Run() != nil {
			// Fallback when running on OpenRC or inside a container without systemd as PID 1
			_ = exec.Command("pkill", "-x", "slapd").Run()
			time.Sleep(100 * time.Millisecond)
			slapdUser, slapdGroup := resolveSlapdUserGroup()
			slapdCmd := exec.Command("/usr/sbin/slapd", "-h", "ldap://127.0.0.1:389/ ldaps:/// ldapi:///", "-g", slapdGroup, "-u", slapdUser, "-F", LDAPConfigDir)
			if out2, err2 := slapdCmd.CombinedOutput(); err2 != nil {
				return "", fmt.Errorf("failed to start slapd: %s / %s (%w)", string(out), string(out2), err2)
			}
			time.Sleep(300 * time.Millisecond)
		}
	}

	// Check if base DIT entry exists; if not, seed the base DIT
	checkCmd := exec.Command("ldapsearch", "-LLL", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", baseDN, "-s", "base", "dn")
	if err := checkCmd.Run(); err != nil {
		log.Printf("[Directory] Seeding base DIT for %s...", baseDN)
		replHash, err := HashSSHA(replPass)
		if err != nil {
			return "", err
		}
		seedLDIF := BuildSlapdSeedDITLDIF(baseDN, firstDC, replHash, policy)
		addCmd := exec.Command("ldapadd", "-c", "-Y", "EXTERNAL", "-H", "ldapi:///")
		addCmd.Stdin = strings.NewReader(seedLDIF)
		out, addErr := addCmd.CombinedOutput()
		if addErr != nil && !strings.Contains(string(out), "Already exists") {
			return "", fmt.Errorf("failed to seed LDAP DIT: %s (%w)", string(out), addErr)
		}
	}

	return baseDN, nil
}
