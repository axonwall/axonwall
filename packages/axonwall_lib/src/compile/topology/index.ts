import {
  TopologyConfigSchema,
  type DesiredState,
  type TopologyCableEdge,
  type TopologyCanvasNode,
  type TopologyConfig,
} from '../../schemas/index.js';
import { isPluginEnabled } from '../../plugins/index.js';

export type HealthTone = 'green' | 'yellow' | 'red';

export interface HostNicProbe {
  hostId: string;
  device: string;
  name?: string;
  role?: string;
  adminUp: boolean;
  carrierUp: boolean;
  speedMbps?: number;
  mtu?: number;
  mac?: string;
  ipv4Addresses?: string[];
  domAlarm?: boolean;
  rxErrors?: number;
  txErrors?: number;
  lldpNeighbors?: Array<{
    chassisName: string;
    portId: string;
    portDescr?: string;
  }>;
}

export interface HostTunnelProbe {
  hostId: string;
  name: string;
  kind: 'wireguard' | 'ipsec' | 'headscale';
  up: boolean;
  handshakeAgeSec?: number;
  peerEndpoint?: string;
}

export interface HostGatewayProbe {
  hostId: string;
  name: string;
  targetIp: string;
  reachable: boolean;
  lossPct?: number;
  latencyMs?: number;
}

export interface K3sResourceProbe {
  nodes: Array<{
    name: string;
    status: string;
    roles?: string;
    internalIp?: string;
    unschedulable?: boolean;
  }>;
  ingresses: Array<{
    name: string;
    namespace: string;
    hosts?: string[];
    backendServices: Array<{ name: string; port?: number }>;
    tlsSecretNames?: string[];
    kind: 'Ingress' | 'IngressRoute' | 'HTTPRoute';
  }>;
  services: Array<{
    name: string;
    namespace: string;
    type?: string;
    clusterIp?: string;
    ports?: number[];
    readyEndpoints: number;
    selector?: Record<string, string>;
  }>;
  workloads: Array<{
    kind: 'Deployment' | 'StatefulSet' | 'DaemonSet';
    name: string;
    namespace: string;
    readyReplicas: number;
    desiredReplicas: number;
    selector?: Record<string, string>;
  }>;
  pvcs: Array<{
    name: string;
    namespace: string;
    storageClass?: string;
    capacity?: string;
    bound: boolean;
    poolName?: string;
  }>;
  networkPolicies: Array<{
    kind: 'NetworkPolicy' | 'CiliumNetworkPolicy';
    name: string;
    namespace: string;
  }>;
}

export interface PeerHostProbe {
  peerId: string;
  name: string;
  role: string;
  reachable: boolean;
  authError?: string;
  error?: string;
  nics: HostNicProbe[];
  tunnels?: HostTunnelProbe[];
}

export interface LibreNmsOverlayProbe {
  available: boolean;
  devices: Array<{
    hostname: string;
    sysName?: string;
    ip?: string;
    status: boolean;
  }>;
  ports: Array<{
    deviceHost: string;
    ifName: string;
    ifOperStatus: string;
    ifAdminStatus?: string;
    ifMtu?: number;
    ifVlan?: string;
    inRateBps?: number;
    outRateBps?: number;
    inErrors?: number;
    outErrors?: number;
  }>;
  links: Array<{
    localDevice: string;
    localPort: string;
    remoteDevice: string;
    remotePort: string;
    protocol: string;
    active: boolean;
  }>;
  alerts: Array<{
    deviceHostname: string;
    portName?: string;
    severity: string;
    rule: string;
    message?: string;
  }>;
}

export interface FabricProbeSnapshot {
  localHostId: string;
  nics: HostNicProbe[];
  tunnels: HostTunnelProbe[];
  gateways: HostGatewayProbe[];
  k3s?: K3sResourceProbe;
  peers: PeerHostProbe[];
  librenms?: LibreNmsOverlayProbe;
}

export interface EndpointHealthResult {
  status: HealthTone;
  reason: string;
  rxBps?: number;
  txBps?: number;
  speedMbps?: number;
  mtu?: number;
}

export interface CableHealthResult {
  status: HealthTone;
  reason: string;
  verifiedBy?: 'lldp' | 'librenms' | 'tunnel' | 'k3s';
  rxBps?: number;
  txBps?: number;
}

export interface FabricHealthEvaluation {
  portHealth: Record<string, EndpointHealthResult>;
  nodeHealth: Record<string, EndpointHealthResult>;
  cableHealth: Record<string, CableHealthResult>;
}

export interface TopologyDiagnostic {
  id: string;
  severity: 'error' | 'warning' | 'info';
  code:
    | 'MTU_MISMATCH'
    | 'VLAN_MISMATCH'
    | 'SUBNET_MISMATCH'
    | 'SUBNET_OVERLAP'
    | 'ORPHAN_INGRESS'
    | 'ZERO_ENDPOINT_SERVICE'
    | 'BROKEN_WAN_ROUTE'
    | 'SPOF_WAN'
    | 'SPOF_K3S_CONTROL'
    | 'PLANNED_CABLE_UNVERIFIED';
  title: string;
  detail: string;
  nodeId?: string;
  edgeId?: string;
  quickFix?: {
    label: string;
    actionType: 'align-cable-mtu' | 'align-cable-vlans' | 'mark-cable-installed';
    patch: Record<string, unknown>;
  };
}

export interface TracedPathHop {
  step: number;
  nodeId: string;
  nodeLabel: string;
  nodeKind: string;
  cableId?: string;
  cableLabel?: string;
  health: HealthTone;
  reason: string;
  matchingNatRules: string[];
  matchingFirewallRules: string[];
  matchingNetworkPolicies: string[];
}

export interface TracedPathResult {
  reachable: boolean;
  overallHealth: HealthTone;
  hops: TracedPathHop[];
}

export interface CompiledLldpdBundle {
  enabled: boolean;
  allowedInterfaces: string[];
  excludedWanInterfaces: string[];
  confContent: string;
}

export interface CompiledTopologyBundle {
  enabled: boolean;
  config: TopologyConfig;
  lldp: CompiledLldpdBundle;
  summary: {
    peersCount: number;
    nodesCount: number;
    cablesCount: number;
    scenariosCount: number;
  };
}

export interface FabricApplyDiffInput {
  localState?: DesiredState;
  peerEdits?: Array<{ peerId: string; name: string; apiUrl: string; state: DesiredState }>;
  k3sEdits?: Array<{
    kind: string;
    name: string;
    namespace?: string;
    manifestYaml?: string;
    scaleReplicas?: number;
    nodeRoles?: string[];
  }>;
  confirmTimeoutSeconds?: number;
}

export interface FabricApplyPlan {
  confirmTimeoutSeconds: number;
  phases: Array<{
    phase: number;
    name: string;
    targets: Array<{ targetType: 'local' | 'peer' | 'k3s'; targetId: string; summary: string }>;
  }>;
}

/**
 * Resolves Topology Studio configuration merged with plugin enablement state.
 */
export function resolveTopologyConfig(state?: Partial<DesiredState> | null): TopologyConfig {
  const parsed = TopologyConfigSchema.parse(state?.topology ?? {});
  return {
    ...parsed,
    enabled: isPluginEnabled('topology-studio', state),
  };
}

function isWanInterface(name: string, role?: string): boolean {
  if (role === 'wan') return true;
  const lower = name.trim().toLowerCase();
  return lower === 'wan' || /^wan\d+$/.test(lower) || lower.startsWith('wan-');
}

/**
 * Compiles `/etc/lldpd.d/axonwall.conf` strictly excluding every WAN interface.
 */
export function compileLldpdConfig(state?: Partial<DesiredState> | null): CompiledLldpdBundle {
  const cfg = resolveTopologyConfig(state);
  const excludedWan = new Set<string>();
  const nonWanDevs = new Set<string>();

  for (const iface of state?.interfaces ?? []) {
    const dev = (iface.device || iface.name || '').trim();
    if (!dev) continue;
    if (isWanInterface(iface.name, iface.role) || isWanInterface(dev, iface.role)) {
      excludedWan.add(dev);
    } else if (iface.enabled) {
      nonWanDevs.add(dev);
    }
  }

  // Always guard WAN default pattern even if excludeWan is passed explicitly
  const allowSet = new Set<string>();
  const requested = cfg.lldp.interfaces ?? [];
  if (requested.length > 0) {
    for (const dev of requested) {
      const clean = dev.trim();
      if (!clean || excludedWan.has(clean) || (cfg.lldp.excludeWan !== false && isWanInterface(clean))) {
        if (clean) excludedWan.add(clean);
        continue;
      }
      allowSet.add(clean);
    }
  } else {
    for (const dev of nonWanDevs) {
      allowSet.add(dev);
    }
  }

  const excludedList = Array.from(excludedWan).sort();
  const allowedList = Array.from(allowSet).sort();

  const patterns: string[] = [];
  for (const w of excludedList) {
    patterns.push(`!${w}`);
  }
  if (!excludedList.includes('wan*') && cfg.lldp.excludeWan !== false) {
    patterns.push('!wan*');
  }
  if (allowedList.length > 0) {
    patterns.push(...allowedList);
  } else if (patterns.length > 0) {
    patterns.push('*');
  }

  const lines = ['# Auto-generated by Axonwall Topology Studio (WAN interfaces strictly excluded)'];
  if (cfg.lldp.enabled) {
    if (patterns.length > 0) {
      lines.push(`configure system interface pattern ${patterns.join(',')}`);
    }
    const sysDesc = (cfg.lldp.systemDescription || 'Axonwall Appliance').replace(/[\r\n"]/g, ' ').trim();
    if (sysDesc) {
      lines.push(`configure system description "${sysDesc}"`);
    }
  } else {
    lines.push('# LLDP discovery is disabled in /etc/axonwall/topology.yaml');
  }

  return {
    enabled: cfg.enabled && cfg.lldp.enabled,
    allowedInterfaces: allowedList,
    excludedWanInterfaces: excludedList,
    confContent: lines.join('\n') + '\n',
  };
}

export function compileTopologyBundle(state?: Partial<DesiredState> | null): CompiledTopologyBundle {
  const cfg = resolveTopologyConfig(state);
  const lldp = compileLldpdConfig(state);
  return {
    enabled: cfg.enabled,
    config: cfg,
    lldp,
    summary: {
      peersCount: cfg.peers.length,
      nodesCount: cfg.nodes.length,
      cablesCount: cfg.cables.length,
      scenariosCount: cfg.scenarios.length,
    },
  };
}

function normId(s?: string): string {
  return (s || '').trim().toLowerCase();
}

function parseIpv4Int(ip: string): number | null {
  const octets = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  return (((octets[0]! << 24) >>> 0) | ((octets[1]! << 16) >>> 0) | ((octets[2]! << 8) >>> 0) | (octets[3]! >>> 0)) >>> 0;
}

function parseCidrRange(cidr?: string): { start: number; end: number } | null {
  if (!cidr || !cidr.includes('/')) return null;
  const [ipStr, prefixStr] = cidr.trim().split('/');
  const prefix = Number.parseInt(prefixStr || '', 10);
  const ipInt = parseIpv4Int(ipStr || '');
  if (ipInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (~((1 << (32 - prefix)) - 1) >>> 0);
  const start = (ipInt & mask) >>> 0;
  const hostMask = (~mask) >>> 0;
  return { start, end: (start | hostMask) >>> 0 };
}

function cidrsIntersect(a?: string, b?: string): boolean {
  const rA = parseCidrRange(a);
  const rB = parseCidrRange(b);
  if (!rA || !rB) return true; // unparseable -> skip false-positive mismatch
  return rA.start <= rB.end && rB.start <= rA.end;
}

function findMatchingNic(
  node: TopologyCanvasNode,
  portName: string,
  probe?: FabricProbeSnapshot | null,
): HostNicProbe | undefined {
  if (!probe) return undefined;
  const hostKey = normId(node.hostRef || probe.localHostId || node.label);
  const pKey = normId(portName);
  const allNics = [
    ...probe.nics,
    ...probe.peers.flatMap((p) => p.nics ?? []),
  ];
  return (
    allNics.find(
      (n) =>
        normId(n.hostId) === hostKey &&
        (normId(n.device) === pKey || normId(n.name) === pKey),
    ) ||
    allNics.find(
      (n) =>
        (normId(node.hostRef) === '' && normId(n.hostId) === normId(probe.localHostId)) &&
        (normId(n.device) === pKey || normId(n.name) === pKey),
    )
  );
}

function findLibreNmsPort(
  node: TopologyCanvasNode,
  portName: string,
  lnms?: LibreNmsOverlayProbe,
) {
  if (!lnms?.available) return undefined;
  const hostKey = normId(node.hostRef || node.label);
  const pKey = normId(portName);
  return lnms.ports.find(
    (p) =>
      (normId(p.deviceHost) === hostKey || normId(p.deviceHost).startsWith(`${hostKey}.`)) &&
      normId(p.ifName) === pKey,
  );
}

/**
 * Evaluates strict tri-state (`green` / `yellow` / `red`) health across every port, node, and cable.
 */
export function evaluateFabricHealth(
  nodes: TopologyCanvasNode[],
  cables: TopologyCableEdge[],
  probe?: FabricProbeSnapshot | null,
): FabricHealthEvaluation {
  const portHealth: Record<string, EndpointHealthResult> = {};
  const nodeHealth: Record<string, EndpointHealthResult> = {};
  const cableHealth: Record<string, CableHealthResult> = {};
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  for (const node of nodes) {
    const peerMatch = probe?.peers.find(
      (p) => normId(p.peerId) === normId(node.hostRef) || normId(p.name) === normId(node.label),
    );
    const activeNodeAlerts = (probe?.librenms?.alerts ?? []).filter(
      (a) =>
        normId(a.deviceHostname) === normId(node.hostRef || node.label) ||
        normId(a.deviceHostname) === normId(node.label),
    );

    const ports =
      node.ports.length > 0
        ? node.ports
        : [{ id: 'default', name: 'default', kind: 'generic' as const, vlanIds: [], planned: !node.managed }];

    let anyRed = false;
    let anyGreen = false;
    let summaryReason = 'Planned / external / unprobed';

    if (peerMatch && !peerMatch.reachable) {
      anyRed = true;
      summaryReason = peerMatch.authError || peerMatch.error || 'Peer host API unreachable';
    }
    const criticalAlert = activeNodeAlerts.find((a) => !a.portName && a.severity === 'critical');
    if (criticalAlert) {
      anyRed = true;
      summaryReason = `LibreNMS alert: ${criticalAlert.rule}`;
    }

    for (const port of ports) {
      const pk = `${node.id}:${port.id}`;
      let res: EndpointHealthResult = { status: 'yellow', reason: 'Unprobed / planned endpoint' };

      const portAlert = activeNodeAlerts.find(
        (a) => a.portName && normId(a.portName) === normId(port.name),
      );
      if (portAlert) {
        res = { status: 'red', reason: `Alert: ${portAlert.rule}` };
      } else if (peerMatch && !peerMatch.reachable) {
        res = { status: 'red', reason: peerMatch.authError || 'Peer unreachable' };
      } else if (port.planned && !node.managed) {
        res = { status: 'yellow', reason: 'Planned / unmanaged endpoint' };
      } else if (node.kind === 'wan') {
        const gw = probe?.gateways.find((g) => normId(g.name) === normId(port.name) || probe.gateways.length === 1);
        if (gw) {
          res = gw.reachable
            ? { status: 'green', reason: `WAN gateway ${gw.targetIp} reachable (${gw.latencyMs ?? 0}ms)` }
            : { status: 'red', reason: `WAN gateway ${gw.targetIp} packet loss (${gw.lossPct ?? 100}%)` };
        } else {
          res = { status: 'yellow', reason: 'External WAN circuit (no active gateway probe)' };
        }
      } else if (node.kind === 'k3s-node') {
        const kNode = probe?.k3s?.nodes.find((kn) => normId(kn.name) === normId(node.hostRef || node.label));
        if (kNode) {
          const isReady = kNode.status.toLowerCase().includes('ready') && !kNode.status.toLowerCase().includes('notready');
          res = isReady
            ? { status: 'green', reason: `Kubernetes Node Ready (${kNode.internalIp || 'internal'})` }
            : { status: 'red', reason: `Kubernetes Node ${kNode.status}` };
        }
      } else if (node.kind === 'k3s-ingress' || node.kind === 'k3s-crd') {
        const ns = String(node.metadata?.namespace || 'default');
        const ing = probe?.k3s?.ingresses.find(
          (i) => normId(i.name) === normId(node.hostRef || node.label) && normId(i.namespace) === normId(ns),
        );
        if (ing) {
          if (ing.backendServices.length === 0) {
            res = { status: 'red', reason: `${ing.kind} has no backend Service` };
          } else {
            const broken = ing.backendServices.find((b) => {
              const svc = probe?.k3s?.services.find((s) => normId(s.name) === normId(b.name) && normId(s.namespace) === normId(ns));
              return !svc || svc.readyEndpoints === 0;
            });
            res = broken
              ? { status: 'red', reason: `Backend Service ${broken.name} missing or has 0 ready endpoints` }
              : { status: 'green', reason: `${ing.kind} backed by ready K3s endpoints` };
          }
        }
      } else if (node.kind === 'k3s-service') {
        const ns = String(node.metadata?.namespace || 'default');
        const svc = probe?.k3s?.services.find(
          (s) => normId(s.name) === normId(node.hostRef || node.label) && normId(s.namespace) === normId(ns),
        );
        if (svc) {
          res =
            svc.readyEndpoints > 0
              ? { status: 'green', reason: `Service ready (${svc.readyEndpoints} endpoint(s))` }
              : { status: 'red', reason: 'Service has 0 ready endpoints' };
        }
      } else if (node.kind === 'k3s-workload') {
        const ns = String(node.metadata?.namespace || 'default');
        const wl = probe?.k3s?.workloads.find(
          (w) => normId(w.name) === normId(node.hostRef || node.label) && normId(w.namespace) === normId(ns),
        );
        if (wl) {
          res =
            wl.desiredReplicas > 0 && wl.readyReplicas >= wl.desiredReplicas
              ? { status: 'green', reason: `${wl.kind} ${wl.readyReplicas}/${wl.desiredReplicas} ready` }
              : { status: 'red', reason: `${wl.kind} degraded (${wl.readyReplicas}/${wl.desiredReplicas} ready)` };
        }
      } else if (node.kind === 'k3s-pvc') {
        const ns = String(node.metadata?.namespace || 'default');
        const pvc = probe?.k3s?.pvcs.find(
          (p) => normId(p.name) === normId(node.hostRef || node.label) && normId(p.namespace) === normId(ns),
        );
        if (pvc) {
          res = pvc.bound
            ? { status: 'green', reason: `PVC Bound (${pvc.storageClass || 'storage'})` }
            : { status: 'red', reason: 'PVC Pending / Unbound' };
        }
      } else if (node.kind === 'vpn-overlay') {
        const tun = probe?.tunnels.find((t) => normId(t.name) === normId(node.hostRef || port.name || node.label));
        if (tun) {
          if (!tun.up || (tun.kind === 'wireguard' && (tun.handshakeAgeSec ?? 0) > 180)) {
            res = { status: 'red', reason: `${tun.kind} tunnel down / stale handshake` };
          } else {
            res = { status: 'green', reason: `${tun.kind} tunnel healthy` };
          }
        }
      } else {
        const nic = findMatchingNic(node, port.name, probe);
        const lPort = findLibreNmsPort(node, port.name, probe?.librenms);
        if (nic) {
          if (!nic.adminUp || !nic.carrierUp || nic.domAlarm || (nic.rxErrors ?? 0) > 0 || (nic.txErrors ?? 0) > 0) {
            res = {
              status: 'red',
              reason: nic.domAlarm
                ? 'Optical DOM alarm detected'
                : !nic.adminUp
                  ? 'Interface administratively down'
                  : !nic.carrierUp
                    ? 'No physical carrier detected'
                    : 'Interface RX/TX errors detected',
              speedMbps: nic.speedMbps,
              mtu: nic.mtu,
              rxBps: lPort?.inRateBps,
              txBps: lPort?.outRateBps,
            };
          } else {
            res = {
              status: 'green',
              reason: lPort
                ? `Carrier up (${nic.speedMbps ?? ''}Mbps) · SNMP healthy`
                : `Carrier up (${nic.speedMbps ?? 'link'}Mbps)`,
              speedMbps: nic.speedMbps,
              mtu: nic.mtu,
              rxBps: lPort?.inRateBps,
              txBps: lPort?.outRateBps,
            };
          }
        } else if (lPort) {
          const hasErr = (lPort.inErrors ?? 0) > 0 || (lPort.outErrors ?? 0) > 0;
          if (lPort.ifOperStatus !== 'up' || hasErr) {
            res = {
              status: 'red',
              reason: hasErr ? 'SNMP port errors detected' : `SNMP ifOperStatus=${lPort.ifOperStatus}`,
              mtu: lPort.ifMtu,
              rxBps: lPort.inRateBps,
              txBps: lPort.outRateBps,
            };
          } else {
            res = {
              status: 'green',
              reason: 'LibreNMS SNMP port up',
              mtu: lPort.ifMtu,
              rxBps: lPort.inRateBps,
              txBps: lPort.outRateBps,
            };
          }
        }
      }

      portHealth[pk] = res;
      if (res.status === 'red') anyRed = true;
      if (res.status === 'green') anyGreen = true;
    }

    nodeHealth[node.id] = anyRed
      ? { status: 'red', reason: summaryReason.startsWith('Planned') ? 'One or more endpoints faulty' : summaryReason }
      : anyGreen
        ? { status: 'green', reason: 'All probed endpoints healthy' }
        : { status: 'yellow', reason: summaryReason };
  }

  for (const cable of cables) {
    const srcNode = nodeMap.get(cable.sourceNodeId);
    const dstNode = nodeMap.get(cable.targetNodeId);
    const srcPortHealth = portHealth[`${cable.sourceNodeId}:${cable.sourcePortId}`];
    const dstPortHealth = portHealth[`${cable.targetNodeId}:${cable.targetPortId}`];
    const srcPortSpec = srcNode?.ports.find((p) => p.id === cable.sourcePortId);
    const dstPortSpec = dstNode?.ports.find((p) => p.id === cable.targetPortId);

    const rxBps = srcPortHealth?.rxBps ?? dstPortHealth?.rxBps;
    const txBps = srcPortHealth?.txBps ?? dstPortHealth?.txBps;

    if (srcPortHealth?.status === 'red' || dstPortHealth?.status === 'red') {
      cableHealth[cable.id] = {
        status: 'red',
        reason: srcPortHealth?.status === 'red' ? srcPortHealth.reason : dstPortHealth!.reason,
        rxBps,
        txBps,
      };
      continue;
    }

    // Config mismatch checks: MTU, VLAN, Subnet
    const mtuA = srcPortHealth?.mtu || srcPortSpec?.mtu;
    const mtuB = dstPortHealth?.mtu || dstPortSpec?.mtu;
    if (mtuA && mtuB && mtuA !== mtuB) {
      cableHealth[cable.id] = {
        status: 'red',
        reason: `MTU mismatch (${mtuA} vs ${mtuB})`,
        rxBps,
        txBps,
      };
      continue;
    }

    const vlansA = srcPortSpec?.vlanIds ?? [];
    const vlansB = dstPortSpec?.vlanIds ?? [];
    if (vlansA.length > 0 && vlansB.length > 0) {
      const setB = new Set(vlansB);
      if (!vlansA.some((v) => setB.has(v))) {
        cableHealth[cable.id] = {
          status: 'red',
          reason: `VLAN mismatch ([${vlansA.join(',')}] vs [${vlansB.join(',')}])`,
          rxBps,
          txBps,
        };
        continue;
      }
    }

    if (srcPortSpec?.subnetCidr && dstPortSpec?.subnetCidr && !cidrsIntersect(srcPortSpec.subnetCidr, dstPortSpec.subnetCidr)) {
      cableHealth[cable.id] = {
        status: 'red',
        reason: `Subnet mismatch (${srcPortSpec.subnetCidr} vs ${dstPortSpec.subnetCidr})`,
        rxBps,
        txBps,
      };
      continue;
    }

    if (cable.layer === 'physical') {
      if (cable.status === 'planned') {
        cableHealth[cable.id] = {
          status: 'yellow',
          reason: 'Planned physical cable (not yet verified live)',
          rxBps,
          txBps,
        };
        continue;
      }

      // Strict end-to-end neighbor proof check (host lldpctl OR LibreNMS LLDP/CDP link)
      const srcPortName = srcPortSpec?.name || cable.sourcePortId;
      const dstPortName = dstPortSpec?.name || cable.targetPortId;
      const srcHost = normId(srcNode?.hostRef || srcNode?.label);
      const dstHost = normId(dstNode?.hostRef || dstNode?.label);

      const srcNic = srcNode ? findMatchingNic(srcNode, srcPortName, probe) : undefined;
      const dstNic = dstNode ? findMatchingNic(dstNode, dstPortName, probe) : undefined;
      const lldpMatched =
        Boolean(
          srcNic?.lldpNeighbors?.some(
            (nb) =>
              (normId(nb.chassisName) === dstHost || normId(nb.chassisName).startsWith(`${dstHost}.`)) &&
              normId(nb.portId) === normId(dstPortName),
          ),
        ) ||
        Boolean(
          dstNic?.lldpNeighbors?.some(
            (nb) =>
              (normId(nb.chassisName) === srcHost || normId(nb.chassisName).startsWith(`${srcHost}.`)) &&
              normId(nb.portId) === normId(srcPortName),
          ),
        );

      const lnmsMatched = Boolean(
        probe?.librenms?.available &&
          probe.librenms.links.some((lk) => {
            if (!lk.active) return false;
            const ld = normId(lk.localDevice);
            const rd = normId(lk.remoteDevice);
            const lp = normId(lk.localPort);
            const rp = normId(lk.remotePort);
            return (
              ((ld === srcHost || ld.startsWith(`${srcHost}.`)) && lp === normId(srcPortName) &&
                (rd === dstHost || rd.startsWith(`${dstHost}.`)) && rp === normId(dstPortName)) ||
              ((ld === dstHost || ld.startsWith(`${dstHost}.`)) && lp === normId(dstPortName) &&
                (rd === srcHost || rd.startsWith(`${srcHost}.`)) && rp === normId(srcPortName))
            );
          }),
      );

      if ((lldpMatched || lnmsMatched) && srcPortHealth?.status === 'green' && dstPortHealth?.status === 'green') {
        cableHealth[cable.id] = {
          status: 'green',
          reason: lnmsMatched ? 'Verified end-to-end via LibreNMS LLDP/CDP' : 'Verified end-to-end via host LLDP',
          verifiedBy: lnmsMatched ? 'librenms' : 'lldp',
          rxBps,
          txBps,
        };
      } else if (srcPortHealth?.status === 'green' || dstPortHealth?.status === 'green') {
        cableHealth[cable.id] = {
          status: 'yellow',
          reason: 'Carrier up, neighbor path unverified (enable lldpd or LibreNMS SNMP/LLDP)',
          rxBps,
          txBps,
        };
      } else {
        cableHealth[cable.id] = {
          status: 'yellow',
          reason: 'Physical path unverified',
          rxBps,
          txBps,
        };
      }
      continue;
    }

    // Virtual / L2-L3 / VPN / K3s links
    if (cable.status === 'planned') {
      cableHealth[cable.id] = { status: 'yellow', reason: 'Planned logical link', rxBps, txBps };
    } else if (srcPortHealth?.status === 'green' && dstPortHealth?.status === 'green') {
      cableHealth[cable.id] = {
        status: 'green',
        reason: cable.layer === 'k3s' ? 'K3s route verified' : 'Link healthy',
        verifiedBy: cable.layer === 'k3s' ? 'k3s' : 'tunnel',
        rxBps,
        txBps,
      };
    } else {
      cableHealth[cable.id] = {
        status: 'yellow',
        reason: 'Endpoint health unverified',
        rxBps,
        txBps,
      };
    }
  }

  return { portHealth, nodeHealth, cableHealth };
}

/**
 * Runs Eluvix-style structural & configuration diagnostics with actionable quick-fix patches.
 */
export function analyzeTopologyDiagnostics(
  nodes: TopologyCanvasNode[],
  cables: TopologyCableEdge[],
  health: FabricHealthEvaluation,
  probe?: FabricProbeSnapshot | null,
): TopologyDiagnostic[] {
  const diagnostics: TopologyDiagnostic[] = [];
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  // 1. Cable-level checks (MTU, VLAN, Subnet, Planned)
  for (const cable of cables) {
    const srcNode = nodeMap.get(cable.sourceNodeId);
    const dstNode = nodeMap.get(cable.targetNodeId);
    const srcPortSpec = srcNode?.ports.find((p) => p.id === cable.sourcePortId);
    const dstPortSpec = dstNode?.ports.find((p) => p.id === cable.targetPortId);
    const srcHealth = health.portHealth[`${cable.sourceNodeId}:${cable.sourcePortId}`];
    const dstHealth = health.portHealth[`${cable.targetNodeId}:${cable.targetPortId}`];

    const mtuA = srcHealth?.mtu || srcPortSpec?.mtu;
    const mtuB = dstHealth?.mtu || dstPortSpec?.mtu;
    if (mtuA && mtuB && mtuA !== mtuB) {
      diagnostics.push({
        id: `diag-mtu-${cable.id}`,
        severity: 'error',
        code: 'MTU_MISMATCH',
        title: `MTU mismatch on ${srcNode?.label || cable.sourceNodeId} <-> ${dstNode?.label || cable.targetNodeId}`,
        detail: `Endpoint MTUs differ (${mtuA} vs ${mtuB}), risking jumbo-frame fragmentation or dropped storage packets.`,
        edgeId: cable.id,
        quickFix: {
          label: `Set both endpoints & cable MTU to ${Math.min(mtuA, mtuB)}`,
          actionType: 'align-cable-mtu',
          patch: { mtu: Math.min(mtuA, mtuB) },
        },
      });
    }

    const vlansA = srcPortSpec?.vlanIds ?? [];
    const vlansB = dstPortSpec?.vlanIds ?? [];
    if (vlansA.length > 0 && vlansB.length > 0 && !vlansA.some((v) => vlansB.includes(v))) {
      const union = Array.from(new Set([...vlansA, ...vlansB])).sort((a, b) => a - b);
      diagnostics.push({
        id: `diag-vlan-${cable.id}`,
        severity: 'error',
        code: 'VLAN_MISMATCH',
        title: `VLAN trunk mismatch on ${cable.cableLabel || cable.id}`,
        detail: `Source VLANs [${vlansA.join(',')}] do not intersect target VLANs [${vlansB.join(',')}].`,
        edgeId: cable.id,
        quickFix: {
          label: `Align allowed VLANs to [${union.join(', ')}]`,
          actionType: 'align-cable-vlans',
          patch: { vlanIds: union },
        },
      });
    }

    if (srcPortSpec?.subnetCidr && dstPortSpec?.subnetCidr && !cidrsIntersect(srcPortSpec.subnetCidr, dstPortSpec.subnetCidr)) {
      diagnostics.push({
        id: `diag-subnet-${cable.id}`,
        severity: 'error',
        code: 'SUBNET_MISMATCH',
        title: `L3 subnet mismatch on ${cable.cableLabel || cable.id}`,
        detail: `${srcPortSpec.subnetCidr} and ${dstPortSpec.subnetCidr} do not overlap on the same link.`,
        edgeId: cable.id,
      });
    }

    if (cable.layer === 'physical' && cable.status === 'planned') {
      diagnostics.push({
        id: `diag-planned-${cable.id}`,
        severity: 'info',
        code: 'PLANNED_CABLE_UNVERIFIED',
        title: `Planned cable ${cable.cableLabel || cable.id}`,
        detail: `${srcNode?.label || cable.sourceNodeId}:${srcPortSpec?.name || cable.sourcePortId} -> ${dstNode?.label || cable.targetNodeId}:${dstPortSpec?.name || cable.targetPortId} (${cable.medium}).`,
        edgeId: cable.id,
        quickFix: {
          label: 'Mark cable as installed',
          actionType: 'mark-cable-installed',
          patch: { status: 'installed' },
        },
      });
    }
  }

  // 2. K3s Ingress / Service health checks & SPOF checks
  for (const node of nodes) {
    const nh = health.nodeHealth[node.id];
    if ((node.kind === 'k3s-ingress' || node.kind === 'k3s-crd') && nh?.status === 'red') {
      diagnostics.push({
        id: `diag-ing-${node.id}`,
        severity: 'error',
        code: 'ORPHAN_INGRESS',
        title: `Broken K3s route: ${node.label}`,
        detail: nh.reason,
        nodeId: node.id,
      });
    } else if (node.kind === 'k3s-service' && nh?.status === 'red') {
      diagnostics.push({
        id: `diag-svc-${node.id}`,
        severity: 'error',
        code: 'ZERO_ENDPOINT_SERVICE',
        title: `K3s Service has 0 ready endpoints: ${node.label}`,
        detail: nh.reason,
        nodeId: node.id,
      });
    } else if (node.kind === 'wan' && nh?.status === 'red') {
      diagnostics.push({
        id: `diag-wan-${node.id}`,
        severity: 'error',
        code: 'BROKEN_WAN_ROUTE',
        title: `WAN upstream fault on ${node.label}`,
        detail: nh.reason,
        nodeId: node.id,
      });
    }
  }

  const wanNodes = nodes.filter((n) => n.kind === 'wan');
  if (wanNodes.length === 1) {
    diagnostics.push({
      id: 'diag-spof-wan',
      severity: 'warning',
      code: 'SPOF_WAN',
      title: 'Single WAN uplink (SPOF)',
      detail: 'Only one WAN circuit node exists on the fabric; add a backup ISP / LTE WAN circuit for multi-WAN failover.',
      nodeId: wanNodes[0]!.id,
    });
  }

  const controlNodes = (probe?.k3s?.nodes ?? []).filter((n) => (n.roles || '').includes('control-plane'));
  if (controlNodes.length === 1) {
    diagnostics.push({
      id: 'diag-spof-k3s',
      severity: 'warning',
      code: 'SPOF_K3S_CONTROL',
      title: 'Single K3s control-plane node',
      detail: 'Only one K3s control-plane node is active; pair with an HA peer or additional control node for etcd quorum.',
    });
  }

  return diagnostics;
}

/**
 * Computes an ordered hop-by-hop trace between any two canvas nodes, annotating NAT/firewall/NetworkPolicy matches.
 */
export function traceFabricPath(
  nodes: TopologyCanvasNode[],
  cables: TopologyCableEdge[],
  health: FabricHealthEvaluation,
  state: Partial<DesiredState> | null,
  sourceNodeId: string,
  targetNodeId: string,
  probe?: FabricProbeSnapshot | null,
): TracedPathResult {
  if (!sourceNodeId || !targetNodeId) {
    return { reachable: false, overallHealth: 'red', hops: [] };
  }
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  if (!nodeMap.has(sourceNodeId) || !nodeMap.has(targetNodeId)) {
    return { reachable: false, overallHealth: 'red', hops: [] };
  }

  // BFS shortest path across undirected cables
  const adj = new Map<string, Array<{ nextId: string; cable: TopologyCableEdge }>>();
  for (const c of cables) {
    const aList = adj.get(c.sourceNodeId) ?? [];
    aList.push({ nextId: c.targetNodeId, cable: c });
    adj.set(c.sourceNodeId, aList);
    const bList = adj.get(c.targetNodeId) ?? [];
    bList.push({ nextId: c.sourceNodeId, cable: c });
    adj.set(c.targetNodeId, bList);
  }

  const queue: string[] = [sourceNodeId];
  const prev = new Map<string, { parent: string; cable: TopologyCableEdge }>();
  const visited = new Set<string>([sourceNodeId]);

  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (cur === targetNodeId) break;
    for (const edge of adj.get(cur) ?? []) {
      if (!visited.has(edge.nextId)) {
        visited.add(edge.nextId);
        prev.set(edge.nextId, { parent: cur, cable: edge.cable });
        queue.push(edge.nextId);
      }
    }
  }

  if (!visited.has(targetNodeId)) {
    return { reachable: false, overallHealth: 'red', hops: [] };
  }

  const chain: Array<{ nodeId: string; incomingCable?: TopologyCableEdge }> = [];
  let cursor: string | undefined = targetNodeId;
  while (cursor) {
    const p = prev.get(cursor);
    chain.push({ nodeId: cursor, incomingCable: p?.cable });
    cursor = p?.parent;
  }
  chain.reverse();

  const hops: TracedPathHop[] = chain.map((item, idx) => {
    const node = nodeMap.get(item.nodeId)!;
    const nh = health.nodeHealth[node.id]?.status ?? 'yellow';
    const ch = item.incomingCable ? (health.cableHealth[item.incomingCable.id]?.status ?? 'yellow') : 'green';
    const hopTone: HealthTone = nh === 'red' || ch === 'red' ? 'red' : nh === 'yellow' || ch === 'yellow' ? 'yellow' : 'green';

    const matchingNatRules: string[] = [];
    const matchingFirewallRules: string[] = [];
    const matchingNetworkPolicies: string[] = [];

    if (node.kind === 'edge-ngfw') {
      for (const nat of state?.nat ?? []) {
        if (nat.enabled !== false) {
          matchingNatRules.push(`${nat.type} (${nat.interface || 'wan'}): ${nat.description || nat.destination || 'NAT'}`);
        }
      }
      for (const rule of (state?.rules ?? []).slice(0, 6)) {
        if (rule.enabled !== false) {
          matchingFirewallRules.push(`${rule.action.toUpperCase()} ${rule.interface}: ${rule.description || rule.protocol}`);
        }
      }
    }
    if (node.kind.startsWith('k3s-') && probe?.k3s?.networkPolicies.length) {
      const ns = String(node.metadata?.namespace || 'default');
      for (const np of probe.k3s.networkPolicies) {
        if (np.namespace === ns) {
          matchingNetworkPolicies.push(`${np.kind}: ${np.namespace}/${np.name}`);
        }
      }
    }

    return {
      step: idx + 1,
      nodeId: node.id,
      nodeLabel: node.label,
      nodeKind: node.kind,
      cableId: item.incomingCable?.id,
      cableLabel: item.incomingCable?.cableLabel || item.incomingCable?.medium,
      health: hopTone,
      reason: item.incomingCable
        ? health.cableHealth[item.incomingCable.id]?.reason || health.nodeHealth[node.id]?.reason || ''
        : health.nodeHealth[node.id]?.reason || 'Source endpoint',
      matchingNatRules,
      matchingFirewallRules,
      matchingNetworkPolicies,
    };
  });

  const worst: HealthTone = hops.some((h) => h.health === 'red')
    ? 'red'
    : hops.some((h) => h.health === 'yellow')
      ? 'yellow'
      : 'green';

  return {
    reachable: worst !== 'red',
    overallHealth: worst,
    hops,
  };
}

function escapeCsvCell(v: string): string {
  let clean = v.replace(/[\r\n]+/g, ' ');
  if (/^[=+\-@\t\r]/.test(clean)) {
    clean = `'${clean}`;
  }
  if (clean.includes(',') || clean.includes('"')) {
    return `"${clean.replace(/"/g, '""')}"`;
  }
  return clean;
}

/**
 * Exports all planned and installed physical cables as CSV, Markdown table, or JSON.
 */
export function exportCableCutSheet(
  nodes: TopologyCanvasNode[],
  cables: TopologyCableEdge[],
  health: FabricHealthEvaluation,
  format: 'csv' | 'markdown' | 'json',
): string {
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const rows = cables
    .filter((c) => c.layer === 'physical' || c.status === 'planned')
    .map((c) => {
      const src = nodeMap.get(c.sourceNodeId);
      const dst = nodeMap.get(c.targetNodeId);
      const srcPort = src?.ports.find((p) => p.id === c.sourcePortId)?.name || c.sourcePortId;
      const dstPort = dst?.ports.find((p) => p.id === c.targetPortId)?.name || c.targetPortId;
      const ch = health.cableHealth[c.id];
      return {
        id: c.id,
        label: c.cableLabel || c.id,
        sourceHost: src?.label || c.sourceNodeId,
        sourcePort: srcPort,
        targetHost: dst?.label || c.targetNodeId,
        targetPort: dstPort,
        medium: c.medium,
        status: c.status,
        speedMbps: c.speedMbps ?? '',
        lengthMeters: c.lengthMeters ?? '',
        color: c.color || '',
        vlans: c.vlanIds.join(','),
        health: ch?.status || 'yellow',
        verification: ch?.reason || '',
      };
    });

  if (format === 'json') {
    return JSON.stringify(rows, null, 2);
  }
  if (format === 'markdown') {
    const header = '| Label | Source | Target | Medium | Status | VLANs | Health | Notes |';
    const sep = '| --- | --- | --- | --- | --- | --- | --- | --- |';
    const body = rows.map(
      (r) =>
        `| ${r.label} | ${r.sourceHost}:${r.sourcePort} | ${r.targetHost}:${r.targetPort} | ${r.medium} | ${r.status} | ${r.vlans || '-'} | ${r.health.toUpperCase()} | ${r.verification} |`,
    );
    return [header, sep, ...body].join('\n');
  }

  const csvHeader = ['Label', 'Source Host', 'Source Port', 'Target Host', 'Target Port', 'Medium', 'Status', 'Speed (Mbps)', 'Length (m)', 'Color', 'VLANs', 'Health', 'Verification'].join(',');
  const csvRows = rows.map((r) =>
    [
      r.label,
      r.sourceHost,
      r.sourcePort,
      r.targetHost,
      r.targetPort,
      r.medium,
      r.status,
      String(r.speedMbps),
      String(r.lengthMeters),
      r.color,
      r.vlans,
      r.health,
      r.verification,
    ]
      .map(escapeCsvCell)
      .join(','),
  );
  return [csvHeader, ...csvRows].join('\n');
}

/**
 * Organizes staged multi-target edits into phased transactional execution order (dry-run -> K3s & peers -> local edge last).
 */
export function buildFabricApplyPlan(input: FabricApplyDiffInput): FabricApplyPlan {
  const timeout = Math.max(10, Math.min(3600, Math.round(input.confirmTimeoutSeconds ?? 120)));
  const validationTargets: FabricApplyPlan['phases'][number]['targets'] = [];
  const remoteAndK3sTargets: FabricApplyPlan['phases'][number]['targets'] = [];
  const edgeTargets: FabricApplyPlan['phases'][number]['targets'] = [];

  for (const k of input.k3sEdits ?? []) {
    const label = `${k.kind} ${k.namespace ? `${k.namespace}/` : ''}${k.name}`;
    validationTargets.push({ targetType: 'k3s', targetId: k.name, summary: `Dry-run validate ${label}` });
    remoteAndK3sTargets.push({ targetType: 'k3s', targetId: k.name, summary: `Apply ${label}` });
  }
  for (const p of input.peerEdits ?? []) {
    validationTargets.push({ targetType: 'peer', targetId: p.peerId, summary: `Preflight peer ${p.name} (${p.apiUrl})` });
    remoteAndK3sTargets.push({ targetType: 'peer', targetId: p.peerId, summary: `Apply peer ${p.name} with ${timeout}s confirm window` });
  }
  if (input.localState) {
    validationTargets.push({ targetType: 'local', targetId: 'local-appliance', summary: 'Compile & validate local /etc/axonwall bundle' });
    edgeTargets.push({ targetType: 'local', targetId: 'local-appliance', summary: `Apply local firewall/network state last with ${timeout}s rollback guard` });
  }

  return {
    confirmTimeoutSeconds: timeout,
    phases: [
      { phase: 1, name: 'Preflight & Dry-Run Validation', targets: validationTargets },
      { phase: 2, name: 'Kubernetes & Remote Peer Hosts', targets: remoteAndK3sTargets },
      { phase: 3, name: 'Local / Edge Firewall (Auto-Confirm Rollback Guard)', targets: edgeTargets },
    ],
  };
}
