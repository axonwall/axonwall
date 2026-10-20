package engine

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// BuildSSSDConfig generates /etc/sssd/sssd.conf connecting to the local OpenLDAP
// daemon (and optional HA peer failover URI) with RFC 2307 schema and SSH public key support.
func BuildSSSDConfig(baseDN string, peerLDAPURI string) string {
	ldapURI := "ldap://127.0.0.1:389"
	tlsBlock := `ldap_id_use_start_tls = False
ldap_tls_reqcert = allow
ldap_auth_disable_tls_never_use_in_production = True`
	if peerLDAPURI != "" {
		ldapURI = fmt.Sprintf("ldap://127.0.0.1:389, %s", peerLDAPURI)
		tlsBlock = fmt.Sprintf(`ldap_id_use_start_tls = False
ldap_tls_reqcert = demand
ldap_tls_cacert = %s
ldap_auth_disable_tls_never_use_in_production = True`, HAPKICACertPath)
	}
	return fmt.Sprintf(`[sssd]
services = nss, pam, ssh
config_file_version = 2
domains = axonwall

[nss]
filter_users = root,axonwall,axonwall-controller,openldap,sshd,nobody
filter_groups = root,axonwall,axonwall-api,axonwall-controller,openldap,sshd,nogroup
entry_negative_timeout = 5

[pam]
offline_credentials_expiration = 7

[ssh]

[domain/axonwall]
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
ldap_uri = %s
ldap_search_base = %s
ldap_schema = rfc2307
ldap_user_search_base = ou=users,%s
ldap_group_search_base = ou=groups,%s
ldap_user_ssh_public_key = sshPublicKey
%s
cache_credentials = True
enumerate = False
entry_cache_timeout = 30
`, ldapURI, baseDN, baseDN, baseDN, tlsBlock)
}

// EnsureSSSDConfigured writes /etc/sssd/sssd.conf (mode 0600), updates /etc/nsswitch.conf
// (`files sss`), enables pam_mkhomedir, registers /usr/local/bin/axonwall-opshell in /etc/shells,
// and starts sssd.
func EnsureSSSDConfigured(baseDN string) error {
	return EnsureSSSDConfiguredWithPeer(baseDN, "")
}

// EnsureSSSDConfiguredWithPeer configures SSSD with optional HA peer LDAPS failover.
func EnsureSSSDConfiguredWithPeer(baseDN string, peerLDAPURI string) error {
	// 1. Register /usr/local/bin/axonwall-opshell in /etc/shells
	if shellsData, err := os.ReadFile("/etc/shells"); err == nil {
		if !strings.Contains(string(shellsData), "/usr/local/bin/axonwall-opshell") {
			updated := strings.TrimRight(string(shellsData), "\n") + "\n/usr/local/bin/axonwall-opshell\n"
			_ = os.WriteFile("/etc/shells", []byte(updated), 0644)
		}
	}

	// 2. Ensure /etc/sudoers.d/axonwall exists with mode 0440
	sudoersPath := "/etc/sudoers.d/axonwall"
	if _, err := os.Stat(sudoersPath); os.IsNotExist(err) {
		_ = os.MkdirAll("/etc/sudoers.d", 0755)
		sudoersContent := `# Managed by Axonwall Identity Engine
Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
%axonwall-admin ALL=(ALL:ALL) ALL
Cmnd_Alias AXONWALL_OP_CMDS = /usr/sbin/axonwall-console, /usr/local/bin/axonwallctl status, /usr/local/bin/axonwallctl diff, /usr/local/bin/axonwallctl validate, /bin/journalctl -u axonwalld -u slapd -u sssd -n 50 --no-pager
%axonwall-operator ALL=(root) NOPASSWD: AXONWALL_OP_CMDS
`
		_ = os.WriteFile(sudoersPath, []byte(sudoersContent), 0440)
	} else {
		_ = os.Chmod(sudoersPath, 0440)
	}

	// 3. Ensure /etc/nsswitch.conf resolves passwd, group, shadow via "files sss"
	if nssData, err := os.ReadFile("/etc/nsswitch.conf"); err == nil {
		lines := strings.Split(string(nssData), "\n")
		changed := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "passwd:") && !strings.Contains(trimmed, "sss") {
				lines[i] = "passwd:         files sss"
				changed = true
			} else if strings.HasPrefix(trimmed, "group:") && !strings.Contains(trimmed, "sss") {
				lines[i] = "group:          files sss"
				changed = true
			} else if strings.HasPrefix(trimmed, "shadow:") && !strings.Contains(trimmed, "sss") {
				lines[i] = "shadow:         files sss"
				changed = true
			}
		}
		if changed {
			_ = os.WriteFile("/etc/nsswitch.conf", []byte(strings.Join(lines, "\n")), 0644)
		}
	}

	// 4. Enable pam_mkhomedir.so in /etc/pam.d/common-session so LDAP users get /home/<user> on first SSH login
	if pamData, err := os.ReadFile("/etc/pam.d/common-session"); err == nil {
		if !strings.Contains(string(pamData), "pam_mkhomedir.so") {
			updated := strings.TrimRight(string(pamData), "\n") + "\nsession required pam_mkhomedir.so skel=/etc/skel umask=0027\n"
			_ = os.WriteFile("/etc/pam.d/common-session", []byte(updated), 0644)
		}
	}

	// 5. Write /etc/sssd/sssd.conf with mode 0600 root:root
	if _, err := exec.LookPath("sssd"); err != nil {
		return fmt.Errorf("sssd binary not installed: %w", err)
	}
	if err := os.MkdirAll("/etc/sssd", 0700); err != nil {
		return err
	}
	confContent := BuildSSSDConfig(baseDN, peerLDAPURI)
	existing, _ := os.ReadFile("/etc/sssd/sssd.conf")
	if string(existing) != confContent {
		if err := os.WriteFile("/etc/sssd/sssd.conf", []byte(confContent), 0600); err != nil {
			return err
		}
		_ = os.Chown("/etc/sssd/sssd.conf", 0, 0)
		_ = exec.Command("systemctl", "enable", "sssd").Run()
		if err := exec.Command("systemctl", "restart", "sssd").Run(); err != nil {
			_ = exec.Command("pkill", "-x", "sssd").Run()
			_ = exec.Command("/usr/sbin/sssd", "-D").Run()
		}
	} else if exec.Command("systemctl", "is-active", "--quiet", "sssd").Run() != nil {
		_ = exec.Command("systemctl", "enable", "sssd").Run()
		if err := exec.Command("systemctl", "restart", "sssd").Run(); err != nil {
			if exec.Command("pgrep", "-x", "sssd").Run() != nil {
				_ = exec.Command("/usr/sbin/sssd", "-D").Run()
			}
		}
	}

	return nil
}

// InvalidateSSSDCache flushes SSSD's local user/group/SSH-key cache after directory mutations.
func InvalidateSSSDCache(username string) {
	if path, err := exec.LookPath("sss_cache"); err == nil {
		if username != "" {
			_ = exec.Command(path, "-u", username).Run()
		}
		_ = exec.Command(path, "-E").Run()
	}
}
