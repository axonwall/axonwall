import React from 'react';
import Link from 'next/link';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';
import {
  Users,
  Lock,
  KeyRound,
  Terminal,
  Shield,
  Layers,
  Network,
  Database,
  CheckCircle2,
  Server,
} from 'lucide-react';

export const metadata = {
  title: 'Unified Identity: Embedded OpenLDAP, SSSD, axonwall-opshell & Enterprise SSO | Axonwall Documentation',
  description:
    'Technical documentation for the Axonwall Unified Identity Architecture: zero-touch embedded OpenLDAP (cn=config + ppolicy) & SSSD, 4-tier RBAC with hardened axonwall-opshell, automatic plugin LDAP provisioning, active-active LDAPS syncrepl HA, OIDC/Entra/Okta/Google SSO, Zero-Trust IAP, and self-service VPN onboarding.',
};

export default function IdentityOpenLdapSsoDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/60 border border-sky-500/30 text-sky-300 text-xs font-semibold">
          <Users className="w-3.5 h-3.5" /> Unified Identity Plane • OpenLDAP + SSSD + OIDC SSO
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Unified Appliance Identity: OpenLDAP, Role Shells &amp; Enterprise SSO
        </h1>
        <p className="text-base text-slate-400 leading-relaxed max-w-3xl">
          Axonwall eliminates fragmented credential silos across the Web Console, SSH/serial CLI, ZFS SMB/NFS shares,
          FreeRADIUS 802.1X, VPN tunnels, and Kubernetes SecOps apps. Every appliance bootstraps a zero-touch embedded{' '}
          <strong className="text-white">OpenLDAP (<code className="font-mono">slapd</code>) + SSSD</strong> directory
          paired with external OIDC/SAML federation, an Identity-Aware Reverse Proxy, and a hardened restricted operator
          shell (<code className="text-emerald-400 font-mono">axonwall-opshell</code>).
        </p>
      </div>

      {/* 1. Zero-Touch Embedded OpenLDAP & SSSD Directory */}
      <section id="openldap-sssd" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-emerald-400" /> 1. Zero-Touch Embedded OpenLDAP (<code className="font-mono text-emerald-400">cn=config</code>) &amp; SSSD
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          On first boot, <code className="text-emerald-400 font-mono">DirectoryManager</code> (<code className="text-slate-200 font-mono">apps/axonwalld/engine/directory.go</code>,{' '}
          <code className="text-slate-200 font-mono">slapd_bootstrap.go</code>, and{' '}
          <code className="text-slate-200 font-mono">sssd.go</code>) automatically initializes an LMDB-backed{' '}
          <code className="text-slate-200 font-mono">slapd</code> instance under{' '}
          <code className="text-slate-200 font-mono">/var/lib/axonwall/ldap/</code> with{' '}
          <code className="text-slate-200 font-mono">back_mdb</code>, <code className="text-slate-200 font-mono">syncprov</code>,{' '}
          <code className="text-slate-200 font-mono">ppolicy</code>, <code className="text-slate-200 font-mono">unique</code>,
          and <code className="text-slate-200 font-mono">accesslog</code> overlays:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400 text-sm flex items-center gap-2">
              <Server className="w-4 h-4" /> Automatic Base DN &amp; ppolicy Enforcement
            </div>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">DeriveBaseDN()</code> converts <code className="text-slate-200 font-mono">system.domain</code>{' '}
              into an RFC 2247 Base DN (e.g. <code className="text-slate-200 font-mono">fw.corp.local</code> &rarr;{' '}
              <code className="text-emerald-300 font-mono">dc=fw,dc=corp,dc=local</code>).{' '}
              <code className="text-slate-200 font-mono">IdentityConfigSchema</code> programs OpenLDAP&apos;s{' '}
              <code className="text-slate-200 font-mono">ppolicy</code> overlay with minimum password length (default{' '}
              <code className="font-mono">12</code>), brute-force lockout (<code className="font-mono">5</code> failures &rarr;{' '}
              <code className="font-mono">900s</code> lockout), password history (<code className="font-mono">5</code>), and
              optional max age.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-sky-400 text-sm flex items-center gap-2">
              <KeyRound className="w-4 h-4" /> SSSD NSS/PAM, SSH Keys &amp; Root SSH Lockdown
            </div>
            <p className="text-slate-400 leading-relaxed">
              Configures <code className="text-slate-200 font-mono">/etc/sssd/sssd.conf</code> (<code className="font-mono">files sss</code>{' '}
              in <code className="font-mono">nsswitch.conf</code> + <code className="font-mono">pam_mkhomedir.so</code>,
              with automatic 15s NSS mirroring on musl/Alpine) and installs{' '}
              <code className="text-slate-200 font-mono">/usr/local/bin/axonwall-ssh-authorizedkeys</code> so{' '}
              <code className="text-slate-200 font-mono">sshd</code> resolves <code className="text-slate-200 font-mono">sshPublicKey</code>{' '}
              attributes directly from LDAP. Once an unlocked <code className="font-mono">admin</code> exists,{' '}
              <code className="text-slate-200 font-mono">disableRootSshWhenAdminExists: true</code> automatically
              disables direct <code className="font-mono">PermitRootLogin</code> while preserving emergency{' '}
              <code className="font-mono">scrypt</code> break-glass recovery.
            </p>
          </div>
        </div>
      </section>

      {/* 2. Four-Tier Appliance RBAC & Hardened axonwall-opshell */}
      <section id="roles-opshell" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-amber-400" /> 2. Four-Tier Appliance RBAC &amp; Hardened <code className="font-mono text-amber-400">axonwall-opshell</code>
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Assigning an <code className="text-emerald-400 font-mono">applianceRole</code> to any directory user
          synchronizes Web Console JWT privileges, POSIX group memberships, <code className="text-slate-200 font-mono">/etc/sudoers.d/axonwall</code>{' '}
          rules, and login shells across the OS:
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-300">
                <th className="py-3 px-4 font-bold">Appliance Role</th>
                <th className="py-3 px-4 font-bold">Assigned Login Shell</th>
                <th className="py-3 px-4 font-bold">OS, SSH &amp; Web Console Capabilities</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-3 px-4 font-mono text-emerald-400 font-semibold">admin</td>
                <td className="py-3 px-4 font-mono">/usr/bin/zsh (/bin/zsh)</td>
                <td className="py-3 px-4">
                  Full superuser across Web Console, API (<code className="font-mono">axonwall-api</code>), Oh My Zsh +
                  Starship interactive shell, Neovim Super Configurator (<code className="font-mono">axonwall-config</code>),
                  and <code className="font-mono">%axonwall-admin NOPASSWD: ALL</code> sudo.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-sky-400 font-semibold">operator</td>
                <td className="py-3 px-4 font-mono">/usr/local/bin/axonwall-opshell</td>
                <td className="py-3 px-4">
                  Operational Console access + restricted SSH menu launching <code className="font-mono">axonwall-tui --readonly</code>,
                  NastyMap diagnostics, <code className="font-mono">axonwallctl status|diff|validate</code>, and bounded
                  journal logs, with a strict SSH <code className="font-mono">-c</code> command allowlist preventing shell escape.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-amber-400 font-semibold">readonly</td>
                <td className="py-3 px-4 font-mono">/usr/sbin/nologin</td>
                <td className="py-3 px-4">
                  Read-only compliance &amp; SOC auditor visibility in the Web Console and REST API with zero interactive
                  SSH or TTY shell login permitted on the host OS.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-purple-400 font-semibold">os_only</td>
                <td className="py-3 px-4 font-mono">/usr/bin/zsh or custom</td>
                <td className="py-3 px-4">
                  Standard POSIX / ZFS SMB share / NFSv4 / FreeRADIUS 802.1X / WireGuard &amp; OpenVPN user account with
                  zero Web Console administrative privileges.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 3. Zero-Touch Plugin Federation */}
      <section id="plugin-federation" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-purple-400" /> 3. Automatic Plugin LDAP Service-Account &amp; Group Provisioning
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Plugins declaring a <code className="text-emerald-400 font-mono">PluginLdapIntegrationSpec</code> never require
          manual LDAP bind setup. <code className="text-slate-200 font-mono">DirectoryManager</code> automatically creates
          isolated bind accounts under <code className="text-slate-200 font-mono">ou=services,&lt;baseDN&gt;</code> with
          unique 192-bit random secrets in <code className="text-slate-200 font-mono">/var/lib/axonwall/secrets/ldap/plugins/</code>,
          writes client binding manifests to <code className="text-slate-200 font-mono">/etc/axonwall/ldap-plugins/</code>,
          and provisions POSIX RBAC groups (<code className="text-emerald-400 font-mono">GIDs 10200–10232</code>) that
          automatically inherit <code className="text-slate-200 font-mono">axonwall-admin</code>,{' '}
          <code className="text-slate-200 font-mono">axonwall-operator</code>, and{' '}
          <code className="text-slate-200 font-mono">axonwall-readonly</code> memberships:
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-300">
                <th className="py-3 px-4 font-bold">Plugin ID</th>
                <th className="py-3 px-4 font-bold">Service Account (ou=services)</th>
                <th className="py-3 px-4 font-bold">Auto-Provisioned POSIX Groups &amp; GIDs</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-400">eluvix</td>
                <td className="py-2.5 px-4 font-mono">cn=svc-eluvix</td>
                <td className="py-2.5 px-4 font-mono">eluvix-admin (10200), eluvix-operator (10201), eluvix-readonly (10202)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-amber-400">freeradius</td>
                <td className="py-2.5 px-4 font-mono">cn=svc-freeradius</td>
                <td className="py-2.5 px-4 font-mono">radius-users (10210)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-sky-400">vigilant-octo-waffle</td>
                <td className="py-2.5 px-4 font-mono">cn=svc-vow</td>
                <td className="py-2.5 px-4 font-mono">vow-admin (10220), vow-operator (10221), vow-readonly (10222)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-400">core-vigilante</td>
                <td className="py-2.5 px-4 font-mono">cn=svc-vigilante</td>
                <td className="py-2.5 px-4 font-mono">vigilante-admin (10230), vigilante-operator (10231), vigilante-readonly (10232)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 4. Active-Active OpenLDAP syncrepl High Availability */}
      <section id="ha-syncrepl" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Network className="w-6 h-6 text-sky-400" /> 4. Active-Active Multi-Provider <code className="font-mono text-sky-400">syncrepl</code> HA &amp; Upgrade Safety
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          When <Link href="/docs/high-availability" className="text-emerald-400 hover:underline">High Availability</Link>{' '}
          is enabled across two Axonwall appliances, OpenLDAP automatically upgrades into a symmetric{' '}
          <strong className="text-white">Active-Active Multi-Provider (<code className="font-mono">olcMirrorMode: TRUE</code>)</strong>{' '}
          pair (<code className="text-slate-200 font-mono">olcServerID 1</code> &amp;{' '}
          <code className="text-slate-200 font-mono">olcServerID 2</code>) using real-time{' '}
          <code className="text-slate-200 font-mono">refreshAndPersist</code> delta-syncrepl over mutual-TLS{' '}
          <code className="text-emerald-400 font-mono">ldaps://:636</code> pinned to the internal HA PKI CA.
        </p>

        <Callout type="info" title="Live ContextCSN Drift Monitoring & Pre-Upgrade LDIF Snapshots">
          <code className="font-mono text-sky-300">DirectoryStatus</code> continuously compares local{' '}
          <code className="font-mono text-sky-300">contextCSN</code> against peer{' '}
          <code className="font-mono text-sky-300">peerContextCSN</code> and NTP clock skew (<code className="font-mono text-sky-300">clockSkewMs</code>),
          while configuring SSSD with dual-URI failover (<code className="font-mono text-sky-300">ldap://127.0.0.1:389, ldaps://&lt;peer&gt;:636</code>).
          Before every A/B image update (<code className="font-mono text-sky-300">axonwall-update</code>),{' '}
          <code className="font-mono text-sky-300">slapcat</code> exports signed <code className="font-mono text-sky-300">cn=config</code>{' '}
          and data LDIF backups into <code className="font-mono text-sky-300">/var/lib/axonwall/ldap/backups/</code>.
        </Callout>
      </section>

      {/* 5. Enterprise OIDC SSO, Zero-Trust IAP & Self-Service VPN Portal */}
      <section id="enterprise-sso" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" /> 5. Enterprise OIDC SSO, Zero-Trust IAP &amp; Self-Service VPN Portal
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          External cloud identity providers, clientless application access, and end-user VPN onboarding are configured
          declaratively in <code className="text-emerald-400 font-mono">/etc/axonwall/security.yaml</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" /> OIDC / Entra / Okta / Google SSO
            </div>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">SsoConfigSchema</code> supports standard{' '}
              <code className="font-mono">oidc</code>, Microsoft <code className="font-mono">entra</code>,{' '}
              <code className="font-mono">okta</code>, and <code className="font-mono">google</code> Workspace, mapping
              IdP <code className="font-mono">groups</code> claims directly into <code className="font-mono">admin</code>,{' '}
              <code className="font-mono">operator</code>, or <code className="font-mono">readonly</code> JWT sessions.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-sky-400" /> Zero-Trust Identity-Aware Proxy
            </div>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">ZeroTrustConfigSchema</code> (<code className="font-mono">engine/iap.go</code>)
              publishes internal HTTP services on <code className="font-mono">publicHostname</code> behind mandatory
              SSO/LDAP session verification and fail-closed <code className="font-mono">allowedRoles</code> checks.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-purple-400" /> Self-Service VPN Portal (<code className="font-mono">/vpn</code>)
            </div>
            <p className="text-slate-400 leading-relaxed">
              Authenticated directory and SSO users can visit the self-service portal at{' '}
              <code className="text-emerald-300 font-mono">/vpn</code> to download personalized WireGuard{' '}
              <code className="font-mono">.conf</code> files, scan mobile WireGuard QR codes, or export OpenVPN client
              bundles without opening IT tickets.
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/security.yaml (SSO & Zero-Trust IAP) + Identity Policy"
          language="yaml"
          code={`# /etc/axonwall/security.yaml
sso:
  enabled: true
  provider: "entra"
  displayName: "Corp Microsoft Entra ID"
  issuerUrl: "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
  clientId: "axonwall-perimeter-console"
  clientSecret: "ENC[scrypt_vault_placeholder]"
  redirectUri: "https://fw.corp.example.com:2966/api/auth/sso/callback"
  scopes: ["openid", "profile", "email", "groups"]
  groupClaim: "groups"
  roleMappings:
    - idpGroup: "NetSec-Platform-Admins"
      role: "admin"
    - idpGroup: "SOC-Tier2-Operators"
      role: "operator"
    - idpGroup: "GRC-Compliance-Auditors"
      role: "readonly"

zeroTrust:
  enabled: true
  apps:
    - name: "Internal Grafana Observability"
      publicHostname: "grafana.corp.example.com"
      internalUpstream: "http://10.10.20.15:3000"
      allowedRoles: ["admin", "operator"]
      allowAnyAuthenticated: false
      enabled: true

# Optional OpenLDAP ppolicy & Root SSH Lockdown (in axonwall.yaml / conf.d/identity.yaml)
identity:
  disableRootSshWhenAdminExists: true
  passwordPolicy:
    minLength: 14
    maxFailures: 5
    lockoutDurationSeconds: 900
    historyCount: 8
    maxAgeDays: 90`}
        />

        <Callout type="tip" title="Manage Directory Users, Groups, LDAPS Sync & SSO in Web Console">
          Create and audit OpenLDAP users, upload <code className="font-mono text-emerald-300">sshPublicKey</code>{' '}
          credentials, inspect live <code className="font-mono text-emerald-300">syncrepl</code> CSN sync status, and
          configure OIDC/Entra/Okta role mappings at <code className="font-mono text-emerald-300">/system/users</code>{' '}
          and <code className="font-mono text-emerald-300">/security/zero-trust</code>.
        </Callout>
      </section>
    </div>
  );
}
