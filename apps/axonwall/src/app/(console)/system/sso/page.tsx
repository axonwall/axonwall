'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Building2,
  Shield,
  CheckCircle2,
  AlertCircle,
  Key,
  Globe,
  RefreshCw,
  ExternalLink,
  Users,
} from 'lucide-react';
import type { SsoConfig } from '@axonwall/lib/schemas';
import { getCurrentDesiredState, testOidcDiscoveryAction } from '@/server/agent';

const PRESET_PROVIDERS = [
  {
    id: 'entra',
    name: 'Microsoft Entra ID (Azure AD)',
    issuerPlaceholder: 'https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0',
    groupClaim: 'groups',
  },
  {
    id: 'okta',
    name: 'Okta Workforce Identity Cloud',
    issuerPlaceholder: 'https://your-domain.okta.com',
    groupClaim: 'groups',
  },
  {
    id: 'google',
    name: 'Google Cloud Identity / Workspace',
    issuerPlaceholder: 'https://accounts.google.com',
    groupClaim: 'email',
  },
  {
    id: 'oidc',
    name: 'Generic OpenID Connect (Keycloak / Authentik)',
    issuerPlaceholder: 'https://auth.company.local/realms/axonwall',
    groupClaim: 'groups',
  },
];

export default function SsoSettingsPage() {
  // C16: an appliance with no SSO configured used to display a fully
  // populated, enabled Entra config belonging to nobody's tenant — and
  // Save applied it, enabling SSO against a wrong issuer. The form now
  // starts empty and disabled; only a saved config replaces it.
  // N3: the form below is READ-ONLY reference. The login flow reads SSO
  // only from the OIDC_* environment variables and never reads the config
  // saved to security.yaml, so the page's Save path was removed entirely
  // rather than keep pretending a save here configures sign-in. What is
  // shown is the last-saved intended IdP, for reference only.
  const [config, setConfig] = useState<SsoConfig>({
    enabled: false,
    provider: 'entra',
    displayName: '',
    issuerUrl: '',
    clientId: '',
    clientSecret: '',
    redirectUri: '',
    scopes: ['openid', 'profile', 'email'],
    groupClaim: 'groups',
    roleMappings: [],
  });

  // null = load not finished yet; false = no saved SSO config exists.
  const [hasSavedConfig, setHasSavedConfig] = useState<boolean | null>(null);
  const [testResult, setTestResult] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        if (state.sso) {
          setConfig(state.sso);
          setHasSavedConfig(true);
        } else {
          setHasSavedConfig(false);
        }
      })
      .catch(() => {
        setHasSavedConfig(false);
      });
  }, []);

  // C4: the test used to be a 1200 ms timer that always reported a
  // verified discovery document. It now performs a real live fetch of
  // the entered issuer's .well-known/openid-configuration and reports
  // the actual outcome, including failures.
  async function handleTestIdP() {
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await testOidcDiscoveryAction(config.issuerUrl);
      setTestResult({ type: res.ok ? 'success' : 'error', text: res.message });
    } catch (err: any) {
      setTestResult({
        type: 'error',
        text: `OIDC discovery test failed: ${err?.message || 'unknown error'}`,
      });
    } finally {
      setIsTesting(false);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Building2 className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Enterprise Single Sign-On (SSO)</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Federate management console authentication and RBAC roles with Microsoft Entra ID, Okta, or OpenID Connect providers.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            href="/system/users"
            className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium px-3.5 py-2 rounded-lg border border-slate-700 transition"
          >
            <Users className="w-4 h-4 text-cyan-400" />
            <span>Local Linux Users</span>
          </Link>
          <button
            type="button"
            onClick={handleTestIdP}
            disabled={isTesting}
            className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium px-3.5 py-2 rounded-lg border border-slate-700 transition cursor-pointer disabled:opacity-50"
          >
            {isTesting ? <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" /> : <Globe className="w-4 h-4 text-emerald-400" />}
            <span>Test IdP Discovery</span>
          </button>
          <a
            href="/api/auth/sso/login"
            target="_blank"
            className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition cursor-pointer flex items-center gap-2 shadow-sm"
          >
            <ExternalLink className="w-4 h-4" />
            <span>Test SSO Login (env config)</span>
          </a>
        </div>
      </div>

      {testResult && (
        <div
          className={`rounded-xl p-4 flex items-center gap-3 text-sm ${
            testResult.type === 'error'
              ? 'bg-red-500/10 border border-red-500/30 text-red-300'
              : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
          }`}
        >
          {testResult.type === 'error' ? (
            <AlertCircle className="w-5 h-5 shrink-0 text-red-400" />
          ) : (
            <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
          )}
          <span>{testResult.text}</span>
        </div>
      )}

      {/* N3: the login flow reads SSO only from environment variables
          (OIDC_ISSUER_URL / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET, plus
          OIDC_ADMIN_GROUPS / OIDC_OPERATOR_GROUPS for roles and a hardcoded
          `groups` claim). It never reads the config saved from this page,
          so this page no longer has a Save action: the form below is a
          read-only display of the last-saved intended IdP, for reference
          only. To change live SSO sign-in, set the OIDC_* variables in
          the appliance environment. */}
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-start gap-3 text-amber-200 text-sm">
        <AlertCircle className="w-5 h-5 shrink-0 text-amber-400 mt-0.5" />
        <span>
          SSO sign-in is environment-configured only. The login flow reads{' '}
          <code className="text-amber-300 font-mono">OIDC_ISSUER_URL</code>,{' '}
          <code className="text-amber-300 font-mono">OIDC_CLIENT_ID</code> and{' '}
          <code className="text-amber-300 font-mono">OIDC_CLIENT_SECRET</code> (roles from{' '}
          <code className="text-amber-300 font-mono">OIDC_ADMIN_GROUPS</code> /{' '}
          <code className="text-amber-300 font-mono">OIDC_OPERATOR_GROUPS</code>); it never reads a
          config saved from this page, including the group claim and role mappings. This page
          shows the last-saved intended IdP for reference only — there is no Save action,
          because saving here cannot change sign-in behaviour.
        </span>
      </div>

      {hasSavedConfig === false && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-center gap-3 text-amber-200 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0 text-amber-400" />
          <span>
            No saved SSO reference config exists on this appliance, and SSO
            sign-in is configured only via the OIDC_* environment variables —
            there is nothing to display here until those are set.
          </span>
        </div>
      )}

      {/* Main Settings Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Identity Provider Parameters */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">SSO Enforcement</h3>
                <p className="text-xs text-slate-400">Enable OpenID Connect authentication on login page</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.enabled}
                  disabled
                  readOnly
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
              </label>
            </div>

            <div className="space-y-4 pt-3 border-t border-slate-800">
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                  Identity Provider Protocol / Vendor
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {PRESET_PROVIDERS.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      disabled
                      className={`p-3 rounded-lg border text-left transition ${
                        config.provider === p.id
                          ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300 font-semibold'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                      }`}
                    >
                      <span className="text-xs block">{p.name}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                  OIDC Issuer URL (Discovery Endpoint)
                </label>
                <input
                  type="text"
                  value={config.issuerUrl}
                  disabled
                  readOnly
                  placeholder="https://login.microsoftonline.com/{tenant-id}/v2.0"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 font-mono text-xs"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                    Client ID / Application ID
                  </label>
                  <input
                    type="text"
                    value={config.clientId}
                    disabled
                    readOnly
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 font-mono text-xs"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                    Client Secret
                  </label>
                  <input
                    type="password"
                    value={config.clientSecret}
                    disabled
                    readOnly
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 font-mono text-xs"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                    Group Claim Key
                  </label>
                  <input
                    type="text"
                    value={config.groupClaim}
                    disabled
                    readOnly
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 font-mono text-xs"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                    Scopes (Comma-separated)
                  </label>
                  <input
                    type="text"
                    value={config.scopes.join(', ')}
                    disabled
                    readOnly
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 font-mono text-xs"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: RBAC Group Role Mappings */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Users className="w-4 h-4 text-emerald-400" />
                <span>Group &rarr; RBAC Role Mapping</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Map IdP directory groups to Axonwall permission roles.
                Reference only — the login flow does not read these mappings
                (see banner above).
              </p>
            </div>

            <div className="space-y-2 max-h-72 overflow-y-auto">
              {config.roleMappings.map((mapping, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between text-xs"
                >
                  <div className="truncate mr-2">
                    <span className="text-slate-200 font-mono block truncate font-medium">
                      {mapping.idpGroup}
                    </span>
                    <span
                      className={`text-[10px] font-semibold uppercase ${
                        mapping.role === 'admin'
                          ? 'text-rose-400'
                          : mapping.role === 'operator'
                          ? 'text-amber-400'
                          : 'text-sky-400'
                      }`}
                    >
                      &rarr; Role: {mapping.role}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
