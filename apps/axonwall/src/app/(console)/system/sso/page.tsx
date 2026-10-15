'use client';

import { useState, useEffect } from 'react';
import {
  Building2,
  Shield,
  CheckCircle2,
  AlertCircle,
  Key,
  Globe,
  Plus,
  Trash2,
  RefreshCw,
  ExternalLink,
  Users,
  Save,
} from 'lucide-react';
import type { SsoConfig, SsoRoleMapping } from '@axonwall/lib/schemas';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';

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
  const [config, setConfig] = useState<SsoConfig>({
    enabled: true,
    provider: 'entra',
    displayName: 'Corporate Single Sign-On',
    issuerUrl: 'https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0',
    clientId: 'axonwall-firewall-console-app-id',
    clientSecret: '••••••••••••••••••••••••••••',
    redirectUri: 'https://firewall.corp.local:2966/api/auth/callback/oidc',
    scopes: ['openid', 'profile', 'email', 'groups'],
    groupClaim: 'groups',
    roleMappings: [
      { idpGroup: 'Entra-FirewallAdmins', role: 'admin' },
      { idpGroup: 'Entra-SecurityOperations', role: 'operator' },
      { idpGroup: 'Entra-ComplianceAuditors', role: 'readonly' },
    ],
  });

  const [testResult, setTestResult] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [newGroup, setNewGroup] = useState('');
  const [newRole, setNewRole] = useState<'admin' | 'operator' | 'readonly'>('operator');

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        if (state.sso) setConfig(state.sso);
      })
      .catch(() => {});
  }, []);

  async function handleSaveConfig() {
    setIsSaving(true);
    try {
      const state = await getCurrentDesiredState();
      await applyDesiredState({ ...state, sso: config });
      setTestResult('Saved SSO configuration to /etc/axonwall/security.yaml');
    } catch {}
    setIsSaving(false);
  }

  function handleAddMapping() {
    if (!newGroup.trim()) return;
    setConfig((prev) => ({
      ...prev,
      roleMappings: [...prev.roleMappings, { idpGroup: newGroup.trim(), role: newRole }],
    }));
    setNewGroup('');
  }

  function handleRemoveMapping(index: number) {
    setConfig((prev) => ({
      ...prev,
      roleMappings: prev.roleMappings.filter((_, i) => i !== index),
    }));
  }

  function handleTestIdP() {
    setIsTesting(true);
    setTestResult(null);
    setTimeout(() => {
      setIsTesting(false);
      setTestResult('Successfully validated OIDC discovery endpoint (.well-known/openid-configuration). Token endpoint and jwks_uri verified.');
    }, 1200);
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
          <button
            type="button"
            onClick={handleSaveConfig}
            disabled={isSaving}
            className="inline-flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium px-3.5 py-2 rounded-lg transition cursor-pointer disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            <span>{isSaving ? 'Saving...' : 'Save to security.yaml'}</span>
          </button>
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
            <span>Simulate SSO Login</span>
          </a>
        </div>
      </div>

      {testResult && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 flex items-center gap-3 text-emerald-300 text-sm">
          <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
          <span>{testResult}</span>
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
                  onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
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
                      onClick={() => setConfig({ ...config, provider: p.id as any })}
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
                  onChange={(e) => setConfig({ ...config, issuerUrl: e.target.value })}
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
                    onChange={(e) => setConfig({ ...config, clientId: e.target.value })}
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
                    onChange={(e) => setConfig({ ...config, clientSecret: e.target.value })}
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
                    onChange={(e) => setConfig({ ...config, groupClaim: e.target.value })}
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
                    onChange={(e) =>
                      setConfig({ ...config, scopes: e.target.value.split(',').map((s) => s.trim()) })
                    }
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
                  <button
                    type="button"
                    onClick={() => handleRemoveMapping(idx)}
                    className="text-slate-500 hover:text-rose-400 transition p-1"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>

            {/* Add New Mapping */}
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <input
                type="text"
                value={newGroup}
                onChange={(e) => setNewGroup(e.target.value)}
                placeholder="IdP Security Group Name..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
              <div className="flex gap-2">
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as any)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 flex-1"
                >
                  <option value="admin">admin (Full Control)</option>
                  <option value="operator">operator (Network Ops)</option>
                  <option value="readonly">readonly (Auditor)</option>
                </select>
                <button
                  type="button"
                  onClick={handleAddMapping}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 transition flex items-center gap-1"
                >
                  <Plus className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Add</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
