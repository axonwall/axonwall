'use client';

import { useState, useEffect } from 'react';
import {
  Server,
  Plus,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  ShieldCheck,
  Save,
  Radio,
  Globe,
  RefreshCw,
} from 'lucide-react';
import { compileKeaDhcp4 } from '@axonwall/lib/compile/kea';
import {
  inferInterfaceRole,
  isInterfaceAuthoritativeDhcp,
  type DesiredState,
  type DhcpConfig,
  type Dhcp6Subnet,
  type Interface,
  type DdnsEntry,
  type UpnpAclRule,
} from '@axonwall/lib/schemas';
import { getCurrentDesiredState, syncDdnsNowAction } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';

const DEFAULT_DHCP: DhcpConfig = {
  enabled: true,
  subnets: [],
};

const DEFAULT_INTERFACES: Interface[] = [
  { name: 'lan', device: 'eth1', type: 'static', enabled: true, description: 'LAN', mtu: 1500 },
];

interface ReservationDraft {
  mac: string;
  ip: string;
  hostname: string;
  desc: string;
}

export default function DhcpPage() {
  const { applyState } = useDesiredStateApply();
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [dhcp, setDhcp] = useState<DhcpConfig>(DEFAULT_DHCP);
  const [interfaces, setInterfaces] = useState<Interface[]>(DEFAULT_INTERFACES);
  const [showKeaConfig, setShowKeaConfig] = useState(false);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  // B19: errors render rose, successes render emerald
  const [statusKind, setStatusKind] = useState<'success' | 'error'>('success');

  // Per-subnet new static mapping form drafts
  const [drafts, setDrafts] = useState<Record<number, ReservationDraft>>({});

  // DHCPv6 / radvd builder state
  const [v6Iface, setV6Iface] = useState('lan');
  const [v6Subnet, setV6Subnet] = useState('2001:db8:10::/64');
  const [v6PoolStart, setV6PoolStart] = useState('2001:db8:10::1000');
  const [v6PoolEnd, setV6PoolEnd] = useState('2001:db8:10::1fff');
  const [v6DelegatedPrefix, setV6DelegatedPrefix] = useState('2001:db8:f000::/56');
  const [v6DelegatedLen, setV6DelegatedLen] = useState(60);
  const [v6RaMode, setV6RaMode] = useState<Dhcp6Subnet['raMode']>('assisted');

  // mDNS Reflector state
  const [mdnsIfacesText, setMdnsIfacesText] = useState('lan, iot');

  // Hardened UPnP ACL builder
  const [upnpCidr, setUpnpCidr] = useState('192.168.1.0/24');
  const [upnpExtPorts, setUpnpExtPorts] = useState('1024-65535');
  const [upnpAction, setUpnpAction] = useState<UpnpAclRule['action']>('allow');

  // Multi-Provider DDNS builder
  const [ddnsProvider, setDdnsProvider] = useState<DdnsEntry['provider']>('cloudflare');
  const [ddnsHostname, setDdnsHostname] = useState('edge.example.com');
  const [ddnsZone, setDdnsZone] = useState('example.com');
  const [ddnsToken, setDdnsToken] = useState('');
  const [ddnsIpVer, setDdnsIpVer] = useState<DdnsEntry['ipVersion']>('dual');

  const getDraft = (idx: number): ReservationDraft =>
    drafts[idx] || { mac: '', ip: '', hostname: '', desc: '' };

  const updateDraft = (idx: number, patch: Partial<ReservationDraft>) => {
    setDrafts((prev) => ({
      ...prev,
      [idx]: { ...getDraft(idx), ...patch },
    }));
  };

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state?.dhcp) {
          setDhcp(state.dhcp);
        }
        if (state?.interfaces?.length) {
          setInterfaces(state.interfaces);
          setV6Iface(state.interfaces.find((i) => inferInterfaceRole(i) === 'lan')?.name || state.interfaces[0].name);
        }
        if (state?.mdnsReflector?.interfaces?.length) {
          setMdnsIfacesText(state.mdnsReflector.interfaces.join(', '));
        }
      })
      .catch(() => {});
  }, []);

  const persistPartialState = async (mutator: (next: DesiredState) => void): Promise<boolean> => {
    const prevFullState = fullState;
    const prevDhcp = dhcp;
    setSaving(true);
    setStatusMsg(null);
    try {
      const current = await getCurrentDesiredState();
      const nextState = structuredClone(current);
      mutator(nextState);
      setFullState(nextState);
      if (nextState.dhcp) setDhcp(nextState.dhcp);
      const res = await applyState(nextState);
      if (res.success) {
        setStatusKind('success');
        setStatusMsg(res.message || 'Saved to /etc/axonwall/services.yaml');
        return true;
      }
      setDhcp(prevDhcp);
      setFullState(prevFullState);
      setStatusKind('error');
      setStatusMsg(res.message || 'Failed to save network services configuration');
      return false;
    } catch (err: any) {
      setDhcp(prevDhcp);
      setFullState(prevFullState);
      setStatusKind('error');
      setStatusMsg(`Error: ${err?.message || 'Failed to save network services configuration'}`);
      return false;
    } finally {
      setSaving(false);
    }
  };

  // B23: report whether the persist actually landed so callers can keep operator's draft when save fails.
  const persistDhcp = async (updatedDhcp: DhcpConfig): Promise<boolean> => {
    setDhcp(updatedDhcp);
    return persistPartialState((next) => {
      next.dhcp = updatedDhcp;
    });
  };

  const handleAddStaticMapping = async (subnetIdx: number, e: React.FormEvent) => {
    e.preventDefault();
    const draft = getDraft(subnetIdx);
    if (!draft.mac.trim() || !draft.ip.trim()) return;
    const mac = draft.mac.trim().toLowerCase();
    const ip = draft.ip.trim();
    const existing = dhcp.subnets[subnetIdx]?.staticMappings ?? [];
    if (existing.some((m) => m.mac.trim().toLowerCase() === mac)) {
      setStatusKind('error');
      setStatusMsg(`A reservation for MAC ${draft.mac.trim()} already exists in this subnet.`);
      return;
    }
    if (existing.some((m) => m.ip.trim() === ip)) {
      setStatusKind('error');
      setStatusMsg(`A reservation for IP ${ip} already exists in this subnet.`);
      return;
    }
    const nextSubnets = dhcp.subnets.map((s, idx) =>
      idx === subnetIdx
        ? {
            ...s,
            staticMappings: [
              ...s.staticMappings,
              {
                mac: draft.mac.trim(),
                ip: draft.ip.trim(),
                hostname: draft.hostname.trim() || undefined,
                description: draft.desc.trim(),
              },
            ],
          }
        : s
    );
    const saved = await persistDhcp({ ...dhcp, subnets: nextSubnets });
    if (saved) {
      updateDraft(subnetIdx, { mac: '', ip: '', hostname: '', desc: '' });
    }
  };

  const handleDeleteStaticMapping = async (subnetIdx: number, mac: string) => {
    const nextSubnets = dhcp.subnets.map((s, idx) =>
      idx === subnetIdx
        ? {
            ...s,
            staticMappings: s.staticMappings.filter((m) => m.mac !== mac),
          }
        : s
    );
    await persistDhcp({ ...dhcp, subnets: nextSubnets });
  };

  const handleUpdatePool = (subnetIdx: number, field: 'poolStart' | 'poolEnd' | 'subnet', value: string) => {
    setDhcp({
      ...dhcp,
      subnets: dhcp.subnets.map((s, idx) => (idx === subnetIdx ? { ...s, [field]: value } : s)),
    });
  };

  const handleAddDhcp6Subnet = async () => {
    if (!v6Subnet.trim()) return;
    const nextSub6: Dhcp6Subnet = {
      interface: v6Iface.trim() || 'lan',
      subnet: v6Subnet.trim(),
      ...(v6PoolStart.trim() ? { poolStart: v6PoolStart.trim() } : {}),
      ...(v6PoolEnd.trim() ? { poolEnd: v6PoolEnd.trim() } : {}),
      ...(v6DelegatedPrefix.trim() ? { delegatedPrefix: v6DelegatedPrefix.trim() } : {}),
      delegatedLen: v6DelegatedLen,
      raMode: v6RaMode,
      dnsServers: [],
      domainSearchList: [],
      staticMappings: [],
      enabled: true,
    };
    const existing6 = dhcp.subnets6 ?? [];
    await persistDhcp({
      ...dhcp,
      dhcp6Enabled: true,
      subnets6: [...existing6.filter((s) => s.interface !== nextSub6.interface), nextSub6],
    });
  };

  const handleDeleteDhcp6Subnet = async (ifaceName: string) => {
    const remaining = (dhcp.subnets6 ?? []).filter((s) => s.interface !== ifaceName);
    await persistDhcp({
      ...dhcp,
      dhcp6Enabled: remaining.length > 0,
      subnets6: remaining,
    });
  };

  const handleSaveMdns = async (enabled: boolean) => {
    const parsedIfaces = mdnsIfacesText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    await persistPartialState((next) => {
      next.mdnsReflector = {
        enabled,
        interfaces: parsedIfaces,
        enableIpv6: next.mdnsReflector?.enableIpv6 ?? true,
        allowSsdpDiscovery: next.mdnsReflector?.allowSsdpDiscovery ?? false,
        description: 'Cross-VLAN mDNS / Bonjour / Matter Reflector',
      };
    });
  };

  const handleAddUpnpAcl = async () => {
    if (!upnpCidr.trim()) return;
    await persistPartialState((next) => {
      const prev = next.upnp || {
        enabled: true,
        externalInterface: 'wan',
        internalInterfaces: ['lan'],
        enableUpnp: true,
        enableNatPmp: true,
        secureMode: true,
        acls: [],
      };
      next.upnp = {
        ...prev,
        enabled: true,
        acls: [
          ...prev.acls,
          {
            action: upnpAction,
            externalPorts: upnpExtPorts.trim() || '1024-65535',
            internalCidr: upnpCidr.trim(),
            internalPorts: '1024-65535',
            description: `${upnpAction.toUpperCase()} UPnP lease rule`,
          },
        ],
      };
    });
  };

  const handleToggleUpnp = async (enabled: boolean) => {
    await persistPartialState((next) => {
      next.upnp = {
        enabled,
        externalInterface: next.upnp?.externalInterface || 'wan',
        internalInterfaces: next.upnp?.internalInterfaces || ['lan'],
        enableUpnp: next.upnp?.enableUpnp ?? true,
        enableNatPmp: next.upnp?.enableNatPmp ?? true,
        secureMode: next.upnp?.secureMode ?? true,
        acls: next.upnp?.acls || [],
      };
    });
  };

  const handleRemoveUpnpAcl = async (idx: number) => {
    await persistPartialState((next) => {
      if (!next.upnp) return;
      next.upnp.acls = next.upnp.acls.filter((_, i) => i !== idx);
    });
  };

  const handleAddDdnsEntry = async () => {
    if (!ddnsHostname.trim()) return;
    await persistPartialState((next) => {
      const prevEntries = next.ddns?.entries || [];
      next.ddns = {
        enabled: true,
        entries: [
          ...prevEntries.filter((e) => e.hostname !== ddnsHostname.trim()),
          {
            provider: ddnsProvider,
            hostname: ddnsHostname.trim(),
            ...(ddnsZone.trim() ? { zone: ddnsZone.trim() } : {}),
            interface: 'wan',
            ipVersion: ddnsIpVer,
            ...(ddnsToken.trim() ? { apiToken: ddnsToken.trim() } : {}),
            checkIntervalSeconds: 300,
            proxied: false,
            enabled: true,
          },
        ],
      };
    });
    setDdnsToken('');
  };

  const handleRemoveDdnsEntry = async (hostname: string) => {
    await persistPartialState((next) => {
      if (!next.ddns) return;
      const remaining = next.ddns.entries.filter((e) => e.hostname !== hostname);
      next.ddns = {
        enabled: remaining.length > 0,
        entries: remaining,
      };
    });
  };

  const handleSyncDdnsNow = async () => {
    try {
      const res = await syncDdnsNowAction();
      setStatusKind(res.success ? 'success' : 'error');
      setStatusMsg(res.message);
    } catch (err: any) {
      setStatusKind('error');
      setStatusMsg(err?.message || 'Failed to trigger DDNS sync');
    }
  };

  const { keaDhcp4Config, keaDhcp6Config, radvdConfig } = compileKeaDhcp4(dhcp, interfaces);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            DHCPv4/v6, SLAAC Router Advertisements &amp; Edge Discovery
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Kea DHCPv4/DHCPv6 (<code className="text-emerald-400 font-mono">IA_NA / IA_PD</code>),{' '}
            <code className="text-cyan-400 font-mono">radvd</code>, Cross-VLAN mDNS Reflector, Hardened UPnP/NAT-PMP, and Multi-Provider DDNS.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => persistDhcp(dhcp)}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Saving YAML...' : 'Save to services.yaml'}</span>
          </button>
          <button
            type="button"
            onClick={() => setShowKeaConfig(!showKeaConfig)}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer border border-slate-700"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>{showKeaConfig ? 'Hide Configs' : 'View Kea4 / Kea6 / radvd'}</span>
          </button>
        </div>
      </div>

      {statusMsg && (
        <div
          className={
            statusKind === 'error'
              ? 'p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300 flex items-center gap-2'
              : 'p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2'
          }
        >
          {statusKind === 'error' ? (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          )}
          <span>{statusMsg}</span>
        </div>
      )}

      {/* Multi-LAN Authoritative vs. Joined Network Safeguard Banner */}
      <div className="p-4 bg-cyan-950/40 border border-cyan-800/40 rounded-xl flex items-start gap-3 text-xs text-cyan-200">
        <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-cyan-300 block text-sm">
            Authoritative DHCP vs. Joined Network Policy
          </span>
          <p className="text-slate-300 leading-relaxed">
            Kea DHCPv4/v6 and <code className="font-mono">radvd</code> bind strictly to <strong>LAN</strong> interfaces configured in{' '}
            <strong>Authoritative DHCP Server</strong> mode. Any LAN interface configured in <strong>Joined Network (Non-authoritative)</strong> mode or any <strong>WAN</strong> uplink is excluded from Kea listener sockets to prevent rogue DHCP/RA collisions.
          </p>
        </div>
      </div>

      {showKeaConfig && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
            <span className="text-xs font-mono text-emerald-400 font-semibold block">
              /etc/kea/kea-dhcp4.conf
            </span>
            <pre className="bg-slate-950 p-3 rounded-lg font-mono text-[11px] text-slate-300 overflow-x-auto max-h-64">
              {keaDhcp4Config}
            </pre>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
            <span className="text-xs font-mono text-cyan-400 font-semibold block">
              /etc/kea/kea-dhcp6.conf
            </span>
            <pre className="bg-slate-950 p-3 rounded-lg font-mono text-[11px] text-slate-300 overflow-x-auto max-h-64">
              {keaDhcp6Config || '# Enable DHCPv6 below to generate kea-dhcp6.conf'}
            </pre>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
            <span className="text-xs font-mono text-amber-400 font-semibold block">
              /etc/radvd.conf
            </span>
            <pre className="bg-slate-950 p-3 rounded-lg font-mono text-[11px] text-slate-300 overflow-x-auto max-h-64">
              {radvdConfig || '# Enable SLAAC/Assisted IPv6 Subnet below to generate radvd.conf'}
            </pre>
          </div>
        </div>
      )}

      {/* Subnets Overview */}
      <div className="grid grid-cols-1 gap-6">
        {dhcp.subnets.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center space-y-2">
            <Server className="w-8 h-8 text-slate-500 mx-auto" />
            <h2 className="text-sm font-semibold text-slate-200">No Authoritative DHCPv4 Subnets Configured</h2>
            <p className="text-xs text-slate-400 max-w-lg mx-auto">
              All LAN interfaces are currently operating in Joined Network (Non-authoritative) mode or unassigned. To enable Kea DHCPv4 on a network port, open the Interfaces page and set a static LAN interface to Authoritative DHCP Server mode.
            </p>
          </div>
        ) : (
          dhcp.subnets.map((sub, subIdx) => {
            const matchedIface = interfaces.find((i) => i.name === sub.interface);
            const isActiveAuth =
              sub.enabled !== false &&
              matchedIface &&
              matchedIface.enabled &&
              inferInterfaceRole(matchedIface) === 'lan' &&
              isInterfaceAuthoritativeDhcp(matchedIface, dhcp);
            const draft = getDraft(subIdx);

            return (
              <div key={`${sub.interface}-${subIdx}`} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-5 h-5 text-emerald-400" />
                    <h2 className="text-base font-bold text-white uppercase">{sub.interface} Subnet</h2>
                    <span className="text-xs bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded border border-slate-700">
                      {sub.subnet}
                    </span>
                  </div>
                  {isActiveAuth ? (
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      Authoritative Active ({matchedIface?.device})
                    </span>
                  ) : (
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      Inactive (Joined Network / Disabled)
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 space-y-2">
                    <span className="text-slate-400 block font-sans">Dynamic IP Pool Range</span>
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={sub.poolStart}
                        onChange={(e) => handleUpdatePool(subIdx, 'poolStart', e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2 py-1 text-emerald-400"
                      />
                      <span className="text-slate-500">-</span>
                      <input
                        type="text"
                        value={sub.poolEnd}
                        onChange={(e) => handleUpdatePool(subIdx, 'poolEnd', e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2 py-1 text-emerald-400"
                      />
                    </div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                    <span className="text-slate-400 block font-sans mb-1">Advertised Gateway</span>
                    <span className="text-slate-200">{sub.routers.join(', ') || 'Auto'}</span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                    <span className="text-slate-400 block font-sans mb-1">DNS Servers</span>
                    <span className="text-slate-200">{sub.dnsServers.join(', ') || 'Auto'}</span>
                  </div>
                </div>

                {/* Static Mappings Table */}
                <div className="space-y-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
                    Static DHCP Reservations
                  </span>
                  <div className="bg-slate-950 border border-slate-800/80 rounded-lg overflow-hidden">
                    {sub.staticMappings.length === 0 ? (
                      <div className="p-6 text-center text-slate-500 text-xs">
                        No static IP reservations configured for {sub.interface}.
                      </div>
                    ) : (
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-slate-900/60 text-slate-400 uppercase border-b border-slate-800">
                          <tr>
                            <th className="px-4 py-2.5">MAC Address</th>
                            <th className="px-4 py-2.5">IP Address</th>
                            <th className="px-4 py-2.5">Hostname</th>
                            <th className="px-4 py-2.5">Description</th>
                            <th className="px-4 py-2.5 text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {sub.staticMappings.map((m) => (
                            <tr key={m.mac} className="hover:bg-slate-900/40">
                              <td className="px-4 py-2.5 text-slate-300">{m.mac}</td>
                              <td className="px-4 py-2.5 text-emerald-400">{m.ip}</td>
                              <td className="px-4 py-2.5 text-white font-sans">{m.hostname || '-'}</td>
                              <td className="px-4 py-2.5 text-slate-400 font-sans">{m.description || '-'}</td>
                              <td className="px-4 py-2.5 text-right">
                                <button
                                  type="button"
                                  onClick={() => handleDeleteStaticMapping(subIdx, m.mac)}
                                  className="text-slate-500 hover:text-red-400 transition"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>

                  {/* Add Static Reservation Form */}
                  <form
                    onSubmit={(e) => handleAddStaticMapping(subIdx, e)}
                    className="grid grid-cols-1 md:grid-cols-5 gap-2 pt-2"
                  >
                    <input
                      type="text"
                      value={draft.mac}
                      onChange={(e) => updateDraft(subIdx, { mac: e.target.value })}
                      placeholder="MAC (aa:bb:cc:dd:ee:ff)"
                      className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                      required
                    />
                    <input
                      type="text"
                      value={draft.ip}
                      onChange={(e) => updateDraft(subIdx, { ip: e.target.value })}
                      placeholder="IPv4 (192.168.1.50)"
                      className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                      required
                    />
                    <input
                      type="text"
                      value={draft.hostname}
                      onChange={(e) => updateDraft(subIdx, { hostname: e.target.value })}
                      placeholder="Hostname (nas-01)"
                      className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
                    />
                    <input
                      type="text"
                      value={draft.desc}
                      onChange={(e) => updateDraft(subIdx, { desc: e.target.value })}
                      placeholder="Description"
                      className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
                    />
                    <button
                      type="submit"
                      disabled={saving}
                      className="bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-medium flex items-center justify-center gap-1.5 transition cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>Add Reservation</span>
                    </button>
                  </form>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* DHCPv6 (IA_NA / IA_PD Prefix Delegation) & radvd SLAAC Router Advertisements */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Kea DHCPv6 (<code className="text-cyan-300 font-mono">IA_NA / IA_PD</code>) &amp; SLAAC Router Advertisements (<code className="text-amber-300 font-mono">radvd</code>)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Stateful IPv6 address pools, downstream router prefix delegation, and RFC 4861 M/O/A-flag router advertisements.
            </p>
          </div>
          <span className="px-2.5 py-1 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 text-xs font-mono">
            {(dhcp.subnets6 ?? []).length} IPv6 Subnets
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-6 gap-3 text-xs">
          <div>
            <label className="block text-slate-400 mb-1">LAN Interface</label>
            <input
              type="text"
              value={v6Iface}
              onChange={(e) => setV6Iface(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">IPv6 Prefix (/64)</label>
            <input
              type="text"
              value={v6Subnet}
              onChange={(e) => setV6Subnet(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">IA_NA Pool Start</label>
            <input
              type="text"
              value={v6PoolStart}
              onChange={(e) => setV6PoolStart(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">IA_NA Pool End</label>
            <input
              type="text"
              value={v6PoolEnd}
              onChange={(e) => setV6PoolEnd(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">IA_PD Pool (/56)</label>
            <input
              type="text"
              value={v6DelegatedPrefix}
              onChange={(e) => setV6DelegatedPrefix(e.target.value)}
              placeholder="Optional"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">RA Mode (radvd)</label>
            <select
              value={v6RaMode}
              onChange={(e) => setV6RaMode(e.target.value as Dhcp6Subnet['raMode'])}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
            >
              <option value="assisted">Assisted (SLAAC + DHCPv6)</option>
              <option value="slaac">SLAAC + RDNSS Only</option>
              <option value="managed">Managed Stateful DHCPv6</option>
              <option value="stateless_dhcp">Stateless DHCPv6</option>
              <option value="disabled">RA Disabled</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>IA_PD Delegated Len:</span>
            <input
              type="number"
              min={48}
              max={64}
              value={v6DelegatedLen}
              onChange={(e) => setV6DelegatedLen(Number(e.target.value))}
              className="w-16 bg-slate-950 border border-slate-800 rounded px-2 py-1 text-white font-mono"
            />
          </div>
          <button
            type="button"
            disabled={saving}
            onClick={handleAddDhcp6Subnet}
            className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" /> Save DHCPv6 &amp; RA Scope
          </button>
        </div>

        {(dhcp.subnets6 ?? []).length > 0 && (
          <div className="space-y-2 pt-2 border-t border-slate-800">
            {(dhcp.subnets6 ?? []).map((s6) => (
              <div key={s6.interface} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <div className="font-mono">
                  <span className="font-bold text-cyan-300 uppercase">{s6.interface}</span>
                  <span className="text-white ml-2">{s6.subnet}</span>
                  {s6.delegatedPrefix && (
                    <span className="text-emerald-400 ml-2">
                      IA_PD: {s6.delegatedPrefix} (/{s6.delegatedLen})
                    </span>
                  )}
                  <span className="text-amber-300 ml-2">[RA: {s6.raMode}]</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleDeleteDhcp6Subnet(s6.interface)}
                  className="text-slate-400 hover:text-rose-400"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Edge Network Services: Cross-VLAN mDNS, Hardened UPnP/NAT-PMP, and Multi-Provider DDNS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Cross-VLAN mDNS Reflector */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400" /> Cross-VLAN mDNS Reflector
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300">
              {fullState?.mdnsReflector?.enabled ? 'ACTIVE' : 'OFF'}
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Reflects Bonjour / AirPlay / Chromecast / Matter multicast discovery strictly across allowlisted LAN/VLAN interfaces (WAN blocked).
          </p>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Reflected Interfaces (comma-separated)</label>
            <input
              type="text"
              value={mdnsIfacesText}
              onChange={(e) => setMdnsIfacesText(e.target.value)}
              placeholder="lan, iot, media"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
            />
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={saving}
              onClick={() => handleSaveMdns(true)}
              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
            >
              Enable mDNS
            </button>
            {fullState?.mdnsReflector?.enabled && (
              <button
                type="button"
                disabled={saving}
                onClick={() => handleSaveMdns(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300"
              >
                Disable
              </button>
            )}
          </div>
        </div>

        {/* Hardened UPnP / NAT-PMP */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-amber-400" /> Hardened UPnP / NAT-PMP
            </h3>
            <button
              type="button"
              onClick={() => handleToggleUpnp(!fullState?.upnp?.enabled)}
              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                fullState?.upnp?.enabled
                  ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {fullState?.upnp?.enabled ? 'ENABLED (SECURE MODE)' : 'DISABLED'}
            </button>
          </div>
          <p className="text-xs text-slate-400">
            Sandboxed <code className="font-mono text-slate-200">miniupnpd</code> in isolated <code className="font-mono text-amber-300">upnp_prerouting</code> nftables chains with explicit CIDR/port ACLs.
          </p>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <select
              value={upnpAction}
              onChange={(e) => setUpnpAction(e.target.value as UpnpAclRule['action'])}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-white font-mono"
            >
              <option value="allow">ALLOW</option>
              <option value="deny">DENY</option>
            </select>
            <input
              type="text"
              value={upnpCidr}
              onChange={(e) => setUpnpCidr(e.target.value)}
              placeholder="192.168.1.50/32"
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-white font-mono"
            />
            <input
              type="text"
              value={upnpExtPorts}
              onChange={(e) => setUpnpExtPorts(e.target.value)}
              placeholder="1024-65535"
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-white font-mono"
            />
          </div>
          <button
            type="button"
            disabled={saving}
            onClick={handleAddUpnpAcl}
            className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-xs font-semibold text-white"
          >
            Add UPnP ACL Rule
          </button>
          {(fullState?.upnp?.acls ?? []).length > 0 && (
            <div className="space-y-1.5 pt-2 border-t border-slate-800">
              {(fullState?.upnp?.acls ?? []).map((acl, i) => (
                <div key={i} className="flex items-center justify-between text-[11px] font-mono bg-slate-950 px-2.5 py-1.5 rounded border border-slate-800">
                  <span className={acl.action === 'allow' ? 'text-emerald-400' : 'text-rose-400'}>
                    {acl.action.toUpperCase()} {acl.externalPorts} → {acl.internalCidr}
                  </span>
                  <button type="button" onClick={() => handleRemoveUpnpAcl(i)} className="text-slate-500 hover:text-rose-400">
                    ✕
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Multi-Provider Dynamic DNS */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" /> Dynamic DNS (DDNS)
            </h3>
            <button
              type="button"
              onClick={handleSyncDdnsNow}
              className="px-2.5 py-1 rounded bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-[11px] font-semibold text-cyan-300 flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" /> Sync Now
            </button>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <select
              value={ddnsProvider}
              onChange={(e) => setDdnsProvider(e.target.value as DdnsEntry['provider'])}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-white font-mono"
            >
              <option value="cloudflare">Cloudflare</option>
              <option value="route53">AWS Route53</option>
              <option value="duckdns">DuckDNS</option>
              <option value="desec">deSEC.io</option>
              <option value="linode">Linode DNS</option>
              <option value="custom">Custom HTTPS</option>
            </select>
            <select
              value={ddnsIpVer}
              onChange={(e) => setDdnsIpVer(e.target.value as DdnsEntry['ipVersion'])}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-white font-mono"
            >
              <option value="dual">Dual-Stack (A+AAAA)</option>
              <option value="ipv4">IPv4 Only (A)</option>
              <option value="ipv6">IPv6 Only (AAAA)</option>
            </select>
            <input
              type="text"
              value={ddnsHostname}
              onChange={(e) => setDdnsHostname(e.target.value)}
              placeholder="edge.example.com"
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-white font-mono"
            />
            <input
              type="text"
              value={ddnsZone}
              onChange={(e) => setDdnsZone(e.target.value)}
              placeholder="Zone (example.com)"
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-white font-mono"
            />
          </div>
          <input
            type="password"
            value={ddnsToken}
            onChange={(e) => setDdnsToken(e.target.value)}
            placeholder="API Token / Secret"
            className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-white font-mono"
          />
          <button
            type="button"
            disabled={saving}
            onClick={handleAddDdnsEntry}
            className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white"
          >
            Add DDNS Record
          </button>
          {(fullState?.ddns?.entries ?? []).length > 0 && (
            <div className="space-y-1.5 pt-2 border-t border-slate-800">
              {(fullState?.ddns?.entries ?? []).map((d) => (
                <div key={d.hostname} className="flex items-center justify-between text-[11px] font-mono bg-slate-950 px-2.5 py-1.5 rounded border border-slate-800">
                  <span className="text-cyan-300 truncate">
                    {d.hostname} <span className="text-slate-400">({d.provider}/{d.ipVersion})</span>
                  </span>
                  <button type="button" onClick={() => handleRemoveDdnsEntry(d.hostname)} className="text-slate-500 hover:text-rose-400">
                    ✕
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
