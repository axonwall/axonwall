import {
  NetFlowConfigSchema,
  ObservabilityConfigSchema,
  ObservabilityOffloadSchema,
  type CaptivePortalConfig,
  type ConntrackSync,
  type NetFlowConfig,
  type ObservabilityConfig,
  type ObservabilityOffloadConfig,
  type SatelliteNode,
  type SuricataConfig,
  type TlsDecryptionConfig,
  type VrrpInstance,
  type WireGuardPeer,
} from '@axonwall/lib/schemas';

export interface SatelliteWifiRadioInput {
  radio: string;
  ssid: string;
  channel?: number;
  security: 'wpa2-psk' | 'wpa3-sae' | 'wpa3-enterprise' | 'open';
  clientsCount: number;
  enabled: boolean;
}

export interface SatelliteNodeViewInput {
  id: string;
  name: string;
  role: 'satellite' | 'edge-ngfw';
  skuProfile?: SatelliteNode['skuProfile'];
  fastpathOffload?: boolean;
  wanInterface?: string;
  lanInterface?: string;
  arch: SatelliteNode['arch'];
  os: string;
  ip: string;
  tunnelIp: string;
  wgConnected: boolean;
  status: SatelliteNode['status'];
  cpuPercent: number;
  memPercent: number;
  activeConns: number;
  offloadedConns: number;
  pid1Mode: boolean;
  uptimeSeconds: number;
  wifiRadios: SatelliteWifiRadioInput[];
  lastSeen: string;
  activePolicyVersion: number;
}

/**
 * Deep-merges UI-editable satellite fields onto existing `SatelliteNode` entries
 * indexed by `id` so non-UI fields (portForwards, zones, ipv6Mode, ipv6Allow,
 * wireguard.publicKey/endpoint, wifi.fastRoaming, ztpToken, etc.) are preserved.
 */
export function mergeSatelliteNodesForPersist(
  existingNodes: readonly SatelliteNode[] | undefined,
  nextViews: readonly SatelliteNodeViewInput[]
): SatelliteNode[] {
  const existingById = new Map((existingNodes ?? []).map((node) => [node.id, node]));

  return nextViews.map((s) => {
    const existing = existingById.get(s.id);
    const existingWifiByRadio = new Map((existing?.wifi ?? []).map((w) => [w.radio, w]));
    const mergedWifi =
      s.wifiRadios.length > 0
        ? s.wifiRadios.map((w) => ({
            ...(existingWifiByRadio.get(w.radio) ?? {}),
            radio: w.radio,
            ssid: w.ssid,
            channel: w.channel,
            security: w.security,
            clientsCount: w.clientsCount,
            enabled: w.enabled,
          }))
        : existing?.wifi ?? [];

    return {
      ...(existing ?? {}),
      id: s.id,
      name: s.name,
      role: s.role,
      skuProfile: s.skuProfile,
      fastpathOffload: s.fastpathOffload ?? true,
      wanInterface: s.wanInterface,
      lanInterface: s.lanInterface,
      arch: s.arch,
      os: s.os,
      ip: s.ip === '—' ? undefined : s.ip,
      lastSeen: s.lastSeen === 'Never' ? undefined : s.lastSeen,
      status: s.status,
      wireguard: {
        ...(existing?.wireguard ?? {}),
        tunnelIp: s.tunnelIp === '—' ? undefined : s.tunnelIp,
        connected: s.wgConnected,
      },
      wifi: mergedWifi,
      metrics: {
        ...(existing?.metrics ?? {}),
        cpuUsagePercent: s.cpuPercent,
        memUsagePercent: s.memPercent,
        uptimeSeconds: s.uptimeSeconds,
        activeConns: s.activeConns,
        offloadedConns: s.offloadedConns,
        pid1Mode: s.pid1Mode,
        rxBytesTotal: existing?.metrics?.rxBytesTotal ?? 0,
        txBytesTotal: existing?.metrics?.txBytesTotal ?? 0,
      },
      activePolicyVersion: s.activePolicyVersion,
    };
  });
}

/**
 * Merges edited WireGuard peers with existing peers so untouched fields such as
 * `presharedKey` (or redacted placeholders) survive adds, toggles, and deletes.
 */
export function mergeWireGuardPeers(
  nextPeers: ReadonlyArray<
    Partial<WireGuardPeer> & {
      name: string;
      publicKey: string;
      allowedIps: string[];
    }
  >,
  existingPeers: readonly WireGuardPeer[] | undefined
): WireGuardPeer[] {
  const byId = new Map<string, WireGuardPeer>();
  const byPubKey = new Map<string, WireGuardPeer>();
  for (const ep of existingPeers ?? []) {
    if (ep.id) byId.set(ep.id, ep);
    if (ep.publicKey) byPubKey.set(ep.publicKey, ep);
  }

  return nextPeers.map((p) => {
    const existing = (p.id ? byId.get(p.id) : undefined) ?? byPubKey.get(p.publicKey);
    const presharedKey = p.presharedKey ?? existing?.presharedKey;
    return {
      ...(existing ?? {}),
      ...(p.id ? { id: p.id } : {}),
      name: p.name,
      publicKey: p.publicKey,
      allowedIps: p.allowedIps,
      endpoint: p.endpoint || undefined,
      persistentKeepalive: p.persistentKeepalive ?? 25,
      enabled: p.enabled ?? true,
      ...(presharedKey ? { presharedKey } : {}),
    };
  });
}

/**
 * Preserves nested `tlsDecryption` and other existing Suricata fields when
 * saving top-level IDS/IPS settings.
 */
export function mergeSuricataConfig(
  existing: SuricataConfig | undefined,
  updates: {
    enabled: boolean;
    mode: SuricataConfig['mode'];
    defaultRuleSources: SuricataConfig['ruleSources'];
    defaultHomeNet: SuricataConfig['homeNet'];
  }
): SuricataConfig {
  return {
    ...(existing ?? {}),
    enabled: updates.enabled,
    mode: updates.mode,
    interfaces: existing?.interfaces || ['wan'],
    nfqueueFailOpen: existing?.nfqueueFailOpen ?? true,
    nfqueueBypass: existing?.nfqueueBypass ?? true,
    ruleSources: existing?.ruleSources || updates.defaultRuleSources,
    homeNet: existing?.homeNet || updates.defaultHomeNet,
  };
}

/**
 * Preserves `caCertificateId` and `transparentProxyPort` when toggling or
 * updating SNI bypass domains on TLS Decryption.
 */
export function mergeTlsDecryptionConfig(
  existing: TlsDecryptionConfig | undefined,
  updates: { enabled: boolean; bypassedDomains: string[] }
): TlsDecryptionConfig {
  return {
    ...(existing ?? {}),
    enabled: updates.enabled,
    transparentProxyPort: existing?.transparentProxyPort ?? 3129,
    bypassedDomains: updates.bypassedDomains,
  };
}

/**
 * Preserves `radiusSecret` and any other top-level Captive Portal fields when
 * adding or deleting zones.
 */
export function mergeCaptivePortalConfig(
  existing: CaptivePortalConfig | undefined,
  zones: CaptivePortalConfig['zones']
): CaptivePortalConfig {
  return {
    ...(existing ?? {}),
    enabled: zones.length > 0,
    zones,
  };
}

/**
 * Updates `virtualIps[0]` while preserving secondary VIPs (`virtualIps[1..N]`).
 */
export function mergeHaVrrpFirstInstance(
  existing: VrrpInstance,
  updates: {
    vrid: number;
    authPassword?: string;
    primaryVip?: string;
  }
): VrrpInstance {
  return {
    ...existing,
    vrid: updates.vrid,
    authPassword: updates.authPassword,
    virtualIps: updates.primaryVip
      ? [updates.primaryVip, ...(existing.virtualIps ?? []).slice(1)]
      : existing.virtualIps,
  };
}

/**
 * Preserves `multicastGroup`, `bufferSize`, `filterIgnoreIps`, and `mode` when
 * saving HA conntrackSync settings.
 */
export function mergeHaConntrackSync(
  existing: ConntrackSync | undefined,
  updates: {
    enabled: boolean;
    syncInterface: string;
    peerIp: string;
  }
): ConntrackSync {
  return {
    ...(existing ?? {}),
    enabled: updates.enabled,
    interface: updates.syncInterface || existing?.interface || 'eth0',
    protocol: existing?.protocol ?? 'unicast',
    peerAddress: updates.peerIp || existing?.peerAddress,
    port: existing?.port ?? 3780,
  };
}

/**
 * Allocates the lowest unused integer >= `minValue` not present in `usedValues`.
 */
export function allocateLowestUnusedInt(
  usedValues: Iterable<number | undefined | null>,
  minValue: number
): number {
  const used = new Set<number>();
  for (const val of usedValues) {
    if (typeof val === 'number' && Number.isInteger(val)) {
      used.add(val);
    }
  }
  let candidate = minValue;
  while (used.has(candidate)) {
    candidate += 1;
  }
  return candidate;
}

/**
 * Allocates the lowest unused `${prefix}${n}` name (starting at `0`) not
 * present in `usedNames`.
 */
export function allocateLowestUnusedSuffixedName(
  usedNames: Iterable<string | undefined | null>,
  prefix: string
): string {
  const used = new Set<string>();
  for (const name of usedNames) {
    if (typeof name === 'string' && name) {
      used.add(name);
    }
  }
  let idx = 0;
  while (used.has(`${prefix}${idx}`)) {
    idx += 1;
  }
  return `${prefix}${idx}`;
}

export function parseCsvTokens(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function parseCsvVlanIds(raw: string): number[] {
  return raw
    .split(',')
    .map((v) => Number(v.trim()))
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 4094);
}

/**
 * Parses a numeric form input allowing `0` without falling back to `fallback`.
 */
export function parseNonNegativeIntInput(raw: string, fallback: number): number {
  const trimmed = raw.trim();
  if (trimmed === '') return 0;
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return Math.trunc(parsed);
}

const DEFAULT_NETFLOW_CONFIG: NetFlowConfig = NetFlowConfigSchema.parse({});

/**
 * Safely fills missing NetFlow sub-objects with schema defaults without calling
 * strict `.parse()` during live typing.
 */
export function resolveNetFlowDraftConfig(raw?: Partial<NetFlowConfig> | null): NetFlowConfig {
  const parsed = NetFlowConfigSchema.safeParse(raw ?? {});
  if (parsed.success) return parsed.data;
  const src = (raw ?? {}) as Partial<NetFlowConfig>;
  return {
    ...DEFAULT_NETFLOW_CONFIG,
    ...src,
    listeners: src.listeners ?? DEFAULT_NETFLOW_CONFIG.listeners,
    exporterProfiles: src.exporterProfiles ?? DEFAULT_NETFLOW_CONFIG.exporterProfiles,
    selfExport: {
      ...DEFAULT_NETFLOW_CONFIG.selfExport,
      ...(src.selfExport ?? {}),
      targets: src.selfExport?.targets ?? DEFAULT_NETFLOW_CONFIG.selfExport.targets,
    },
    replicator: {
      ...DEFAULT_NETFLOW_CONFIG.replicator,
      ...(src.replicator ?? {}),
      targets: src.replicator?.targets ?? DEFAULT_NETFLOW_CONFIG.replicator.targets,
    },
    storage: {
      ...DEFAULT_NETFLOW_CONFIG.storage,
      ...(src.storage ?? {}),
      clickhouse: {
        ...DEFAULT_NETFLOW_CONFIG.storage.clickhouse,
        ...(src.storage?.clickhouse ?? {}),
      },
    },
    enrichment: {
      ...DEFAULT_NETFLOW_CONFIG.enrichment,
      ...(src.enrichment ?? {}),
      internalCidrs: src.enrichment?.internalCidrs ?? DEFAULT_NETFLOW_CONFIG.enrichment.internalCidrs,
      customPortApps: src.enrichment?.customPortApps ?? DEFAULT_NETFLOW_CONFIG.enrichment.customPortApps,
    },
    alerting: {
      ...DEFAULT_NETFLOW_CONFIG.alerting,
      ...(src.alerting ?? {}),
      rules: src.alerting?.rules ?? DEFAULT_NETFLOW_CONFIG.alerting.rules,
    },
    topologyOverlay: {
      ...DEFAULT_NETFLOW_CONFIG.topologyOverlay,
      ...(src.topologyOverlay ?? {}),
    },
    reporting: {
      ...DEFAULT_NETFLOW_CONFIG.reporting,
      ...(src.reporting ?? {}),
    },
    savedViews: src.savedViews ?? DEFAULT_NETFLOW_CONFIG.savedViews,
  };
}

const DEFAULT_OBS_CONFIG: ObservabilityConfig = ObservabilityConfigSchema.parse({});
const DEFAULT_OBS_OFFLOAD: ObservabilityOffloadConfig = ObservabilityOffloadSchema.parse({});

/**
 * Safely fills missing Observability + Offload sub-objects with schema defaults
 * without calling strict `.parse()` during live typing.
 */
export function resolveObservabilityDraftConfig(
  raw?: Partial<ObservabilityConfig> | null
): ObservabilityConfig & { offload: ObservabilityOffloadConfig } {
  const src = (raw ?? {}) as Partial<ObservabilityConfig>;
  const offSrc = (src.offload ?? {}) as Partial<ObservabilityOffloadConfig>;
  return {
    ...DEFAULT_OBS_CONFIG,
    ...src,
    metrics: { ...DEFAULT_OBS_CONFIG.metrics, ...(src.metrics ?? {}) },
    flowExport: { ...DEFAULT_OBS_CONFIG.flowExport, ...(src.flowExport ?? {}) },
    alerting: { ...DEFAULT_OBS_CONFIG.alerting, ...(src.alerting ?? {}) },
    clickhouse: { ...DEFAULT_OBS_CONFIG.clickhouse, ...(src.clickhouse ?? {}) },
    offload: {
      ...DEFAULT_OBS_OFFLOAD,
      ...offSrc,
      ipfix: { ...DEFAULT_OBS_OFFLOAD.ipfix, ...(offSrc.ipfix ?? {}) },
      metrics: { ...DEFAULT_OBS_OFFLOAD.metrics, ...(offSrc.metrics ?? {}) },
      logs: {
        ...DEFAULT_OBS_OFFLOAD.logs,
        ...(offSrc.logs ?? {}),
        nflog: { ...DEFAULT_OBS_OFFLOAD.logs.nflog, ...(offSrc.logs?.nflog ?? {}) },
        journald: { ...DEFAULT_OBS_OFFLOAD.logs.journald, ...(offSrc.logs?.journald ?? {}) },
        suricata: { ...DEFAULT_OBS_OFFLOAD.logs.suricata, ...(offSrc.logs?.suricata ?? {}) },
        crowdsec: { ...DEFAULT_OBS_OFFLOAD.logs.crowdsec, ...(offSrc.logs?.crowdsec ?? {}) },
        keaDhcp: { ...DEFAULT_OBS_OFFLOAD.logs.keaDhcp, ...(offSrc.logs?.keaDhcp ?? {}) },
        unboundDns: { ...DEFAULT_OBS_OFFLOAD.logs.unboundDns, ...(offSrc.logs?.unboundDns ?? {}) },
      },
      buffer: { ...DEFAULT_OBS_OFFLOAD.buffer, ...(offSrc.buffer ?? {}) },
      activeMitigation: {
        ...DEFAULT_OBS_OFFLOAD.activeMitigation,
        ...(offSrc.activeMitigation ?? {}),
      },
    },
  };
}
