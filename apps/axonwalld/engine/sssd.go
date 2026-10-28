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
	caCertPath := ""
	if _, err := os.Stat("/etc/axonwall/pki/ca.crt"); err == nil {
		caCertPath = "/etc/axonwall/pki/ca.crt"
	} else if _, err := os.Stat(HAPKICACertPath); err == nil {
		caCertPath = HAPKICACertPath
	}

	var tlsBlock string
	if peerLDAPURI != "" {
		ldapURI = fmt.Sprintf("ldap://127.0.0.1:389, %s", peerLDAPURI)
		if caCertPath == "" {
			caCertPath = HAPKICACertPath
		}
		tlsBlock = fmt.Sprintf(`ldap_id_use_start_tls = False
ldap_tls_reqcert = demand
ldap_tls_cacert = %s`, caCertPath)
	} else if caCertPath != "" {
		tlsBlock = fmt.Sprintf(`ldap_id_use_start_tls = False
ldap_tls_reqcert = demand
ldap_tls_cacert = %s`, caCertPath)
	} else {
		tlsBlock = `ldap_id_use_start_tls = False
ldap_tls_reqcert = never`
	}
	return fmt.Sprintf(`[sssd]
services = nss, pam, ssh
config_file_version = 2
domains = axonwall

[nss]
filter_users = root,axonwall,axonwall-controller,openldap,sshd,nobody
filter_groups = root,axonwall,axonwall-api,axonwall-controller,openldap,sshd,nogroup
default_shell = /usr/bin/zsh
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

// hasSSSD returns true if the SSSD daemon binary is installed on the host OS (Debian/glibc).
func hasSSSD() bool {
	_, err := exec.LookPath("sssd")
	return err == nil
}

// EnsureAuthorizedKeysHelperInstalled writes /usr/local/bin/axonwall-ssh-authorizedkeys
// and symlinks /usr/bin/sss_ssh_authorizedkeys to it if sss_ssh_authorizedkeys is absent (e.g. Alpine/musl),
// enabling sshd AuthorizedKeysCommand to resolve sshPublicKey directly from OpenLDAP.
func EnsureAuthorizedKeysHelperInstalled() {
	helperPath := "/usr/local/bin/axonwall-ssh-authorizedkeys"
	helperScript := `#!/bin/sh
# Managed by Axonwall Identity Engine — OpenLDAP SSH AuthorizedKeysCommand helper
USER_ARG="${1:-}"
case "$USER_ARG" in
  ""|*[!a-z0-9_-]*) exit 0 ;;
esac
BASE_DN="dc=axonwall,dc=local"
if [ -r /var/lib/axonwall/ldap/BASE_DN ]; then
  ReadDN="$(tr -d '[:space:]' < /var/lib/axonwall/ldap/BASE_DN)"
  [ -n "$ReadDN" ] && BASE_DN="$ReadDN"
fi
if command -v ldapsearch >/dev/null 2>&1; then
  ldapsearch -LLL -o ldif-wrap=no -x -H ldap://127.0.0.1:389 \
    -b "ou=users,${BASE_DN}" "(uid=${USER_ARG})" sshPublicKey 2>/dev/null \
    | sed -n 's/^sshPublicKey: //p'
fi
if [ -r "/home/${USER_ARG}/.ssh/authorized_keys" ]; then
  cat "/home/${USER_ARG}/.ssh/authorized_keys" 2>/dev/null || true
fi
`
	_ = os.MkdirAll("/usr/local/bin", 0755)
	if err := os.WriteFile(helperPath, []byte(helperScript), 0755); err == nil {
		_ = os.Chmod(helperPath, 0755)
	}
	if _, err := os.Stat("/usr/bin/sss_ssh_authorizedkeys"); os.IsNotExist(err) {
		_ = os.MkdirAll("/usr/bin", 0755)
		_ = os.Symlink(helperPath, "/usr/bin/sss_ssh_authorizedkeys")
	}
}

// EnsureSSSDConfigured writes /etc/sssd/sssd.conf (mode 0600), updates /etc/nsswitch.conf
// (`files sss`), enables pam_mkhomedir, registers /usr/local/bin/axonwall-opshell in /etc/shells,
// and starts sssd (or configures the lightweight OpenLDAP NSS/SSH bridge on Alpine/musl).
func EnsureSSSDConfigured(baseDN string) error {
	return EnsureSSSDConfiguredWithPeer(baseDN, "")
}

// EnsureSSSDConfiguredWithPeer configures SSSD with optional HA peer LDAPS failover.
func EnsureSSSDConfiguredWithPeer(baseDN string, peerLDAPURI string) error {
	// 0. On minimal appliances (e.g., Alpine MINIMAL=1) where /usr/bin/zsh is not installed,
	// symlink /usr/bin/zsh -> /bin/ash (or /bin/sh) so LDAP users with loginShell=/usr/bin/zsh
	// (including users replicated from a Debian HA node) can log in over SSH cleanly.
	if _, err := os.Stat("/usr/bin/zsh"); os.IsNotExist(err) {
		if _, err := os.Stat("/bin/zsh"); err == nil {
			_ = os.Symlink("/bin/zsh", "/usr/bin/zsh")
		} else if _, err := os.Stat("/bin/ash"); err == nil {
			_ = os.Symlink("/bin/ash", "/usr/bin/zsh")
		} else {
			_ = os.Symlink("/bin/sh", "/usr/bin/zsh")
		}
	}

	EnsureAuthorizedKeysHelperInstalled()

	// 1. Register /usr/local/bin/axonwall-opshell and /usr/bin/zsh in /etc/shells
	if shellsData, err := os.ReadFile("/etc/shells"); err == nil {
		updated := strings.TrimRight(string(shellsData), "\n")
		changed := false
		for _, sh := range []string{"/usr/bin/zsh", "/bin/zsh", "/usr/local/bin/axonwall-opshell"} {
			if !strings.Contains(updated+"\n", sh+"\n") {
				updated += "\n" + sh
				changed = true
			}
		}
		if changed {
			_ = os.WriteFile("/etc/shells", []byte(updated+"\n"), 0644)
		}
	}

	// 2. Ensure /etc/sudoers.d/axonwall exists with mode 0440
	sudoersPath := "/etc/sudoers.d/axonwall"
	if _, err := os.Stat(sudoersPath); os.IsNotExist(err) {
		_ = os.MkdirAll("/etc/sudoers.d", 0755)
		sudoersContent := `# Managed by Axonwall Identity Engine
Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
%axonwall-admin ALL=(ALL:ALL) NOPASSWD: ALL
Cmnd_Alias AXONWALL_OP_CMDS = /usr/local/bin/axonwall-tui --readonly, /usr/local/bin/axonwall-tui --readonly --tab nastymap, /usr/local/bin/axonwall-tui --tab nastymap --readonly, /usr/local/bin/axonwall-tui --readonly --view=nastymap, /usr/local/bin/axonwallctl status, /usr/local/bin/axonwallctl diff, /usr/local/bin/axonwallctl validate, /bin/journalctl -u axonwalld -u slapd -u sssd -n 50 --no-pager
%axonwall-operator ALL=(root) NOPASSWD: AXONWALL_OP_CMDS
`
		_ = os.WriteFile(sudoersPath, []byte(sudoersContent), 0440)
	} else {
		_ = os.Chmod(sudoersPath, 0440)
	}

	// If SSSD is not installed (e.g. Alpine Linux / musl libc), DirectoryManager mirrors
	// LDAP POSIX entries directly into /etc/passwd and /etc/group and uses axonwall-ssh-authorizedkeys.
	if !hasSSSD() {
		return nil
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
