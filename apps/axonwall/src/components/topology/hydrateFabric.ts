import type { FabricProbeSnapshot } from '@axonwall/lib/compile/topology';
import type {
  DesiredState,
  TopologyCableEdge,
  TopologyCanvasNode,
  TopologyPortSpec,
} from '@axonwall/lib/schemas';
import type { TopologyFabricSnapshot } from '@/server/agent';
import { autoLayoutTopologyNodes } from './autoLayout';

export function buildProbeSnapshotForEval(
  fabric: TopologyFabricSnapshot | null,
  state: DesiredState | null,
): FabricProbeSnapshot {
  const localHostId = fabric?.local?.localHostId || state?.system?.hostname || 'axonwall-local';
  const gateways = (state?.gateways ?? []).map((gw) => ({
    hostId: localHostId,
    name: gw.name,
    targetIp: gw.monitorIp || gw.gatewayIp || '',
    reachable: true,
    lossPct: 0,
    latencyMs: 0,
  }));

  return {
    localHostId,
    nics: fabric?.local?.nics ?? [],
    tunnels: fabric?.local?.tunnels ?? [],
    gateways,
    k3s: fabric?.local?.k3s
      ? {
          nodes: fabric.local.k3s.nodes,
          ingresses: fabric.local.k3s.ingresses.map((i) => ({
            ...i,
            kind: i.kind,
          })),
          services: fabric.local.k3s.services,
          workloads: fabric.local.k3s.workloads,
          pvcs: fabric.local.k3s.pvcs.map((p) => ({ ...p })),
          networkPolicies: fabric.local.k3s.networkPolicies,
        }
      : undefined,
    peers: fabric?.peers ?? [],
    librenms: fabric?.librenms
      ? {
          available: fabric.librenms.available,
          devices: fabric.librenms.devices,
          ports: fabric.librenms.ports.map((p) => ({
            deviceHost: p.deviceHost || '',
            ifName: p.ifName,
            ifOperStatus: p.ifOperStatus,
            ifAdminStatus: p.ifAdminStatus,
            ifMtu: p.ifMtu,
            ifVlan: p.ifVlan,
            inRateBps: p.inRateBps,
            outRateBps: p.outRateBps,
            inErrors: p.inErrors,
            outErrors: p.outErrors,
          })),
          links: fabric.librenms.links.map((l) => ({
            localDevice: l.localDevice || '',
            localPort: l.localPort,
            remoteDevice: l.remoteDevice,
            remotePort: l.remotePort,
            protocol: l.protocol,
            active: l.active,
          })),
          alerts: fabric.librenms.alerts,
        }
      : undefined,
  };
}

function slugId(prefix: string, raw: string): string {
  const clean = raw
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return `${prefix}-${clean || 'node'}`;
}

function mergePorts(existing: TopologyPortSpec[], discovered: TopologyPortSpec[]): TopologyPortSpec[] {
  const byId = new Map<string, TopologyPortSpec>();
  for (const p of existing) byId.set(p.id, p);
  for (const p of discovered) {
    const prev = byId.get(p.id);
    if (!prev) {
      byId.set(p.id, p);
    } else {
      byId.set(p.id, {
        ...p,
        ...prev,
        speedMbps: prev.speedMbps ?? p.speedMbps,
        mtu: prev.mtu ?? p.mtu,
        subnetCidr: prev.subnetCidr ?? p.subnetCidr,
        vlanIds: prev.vlanIds?.length ? prev.vlanIds : p.vlanIds,
      });
    }
  }
  return Array.from(byId.values());
}

/**
 * Combines saved `topology.yaml` nodes & cables (or an active What-If scenario) with
 * live discovered local, HA, fleet, peer, LibreNMS, K3s, and Virt objects.
 */
export function hydrateFabricGraph(
  state: DesiredState | null,
  fabric: TopologyFabricSnapshot | null,
  savedNodes: TopologyCanvasNode[],
  savedCables: TopologyCableEdge[],
): { nodes: TopologyCanvasNode[]; cables: TopologyCableEdge[] } {
  const nodeMap = new Map<string, TopologyCanvasNode>();
  const savedPositions = new Map<string, { x: number; y: number }>();

  for (const n of savedNodes) {
    nodeMap.set(n.id, structuredClone(n));
    savedPositions.set(n.id, n.position);
  }

  const upsertDiscoveredNode = (candidate: TopologyCanvasNode) => {
    const prev = nodeMap.get(candidate.id);
    if (!prev) {
      nodeMap.set(candidate.id, candidate);
    } else {
      nodeMap.set(candidate.id, {
        ...candidate,
        ...prev,
        position: savedPositions.get(candidate.id) ?? candidate.position,
        ports: mergePorts(prev.ports ?? [], candidate.ports ?? []),
        metadata: { ...(candidate.metadata ?? {}), ...(prev.metadata ?? {}) },
      });
    }
  };

  const localHostName = fabric?.local?.localHostId || state?.system?.hostname || 'axonwall-edge';
  const localHostId = slugId('host', localHostName);
  const localPorts: TopologyPortSpec[] = [];
  const wanInterfaces = (state?.interfaces ?? []).filter((i) => i.role === 'wan' && i.enabled);
  const hasFirewall = state?.capabilities?.firewallEnabled !== false;
  const localKind: TopologyCanvasNode['kind'] = hasFirewall
    ? 'edge-ngfw'
    : state?.capabilities?.nasEnabled
      ? 'nas'
      : state?.capabilities?.k3sEnabled
        ? 'k3s-node'
        : 'generic-host';

  for (const ifc of state?.interfaces ?? []) {
    if (!ifc.enabled) continue;
    const dev = ifc.device || ifc.name;
    const probeNic = fabric?.local?.nics.find((n) => n.device === dev || n.name === ifc.name);
    localPorts.push({
      id: dev,
      name: `${ifc.name} (${dev})`,
      kind: ifc.role === 'wan' ? 'wan-uplink' : 'physical-nic',
      speedMbps: probeNic?.speedMbps || undefined,
      mtu: ifc.mtu || probeNic?.mtu || 1500,
      vlanIds: [],
      subnetCidr: ifc.ipv4Address || undefined,
      planned: false,
    });
  }
  for (const nic of fabric?.local?.nics ?? []) {
    if (!localPorts.some((p) => p.id === nic.device)) {
      localPorts.push({
        id: nic.device,
        name: nic.device,
        kind: 'physical-nic',
        speedMbps: nic.speedMbps || undefined,
        mtu: nic.mtu || undefined,
        vlanIds: [],
        subnetCidr: nic.ipv4Addresses?.[0],
        planned: false,
      });
    }
  }
  if (localPorts.length === 0) {
    localPorts.push({ id: 'eth0', name: 'eth0', kind: 'physical-nic', vlanIds: [], planned: false });
  }

  upsertDiscoveredNode({
    id: localHostId,
    kind: localKind,
    label: localHostName,
    hostRef: localHostName,
    layer: 'physical',
    managed: true,
    position: { x: 380, y: 120 },
    ports: localPorts,
    metadata: { role: localKind, domain: state?.system?.domain || 'axonwall.local' },
  });

  const cableMap = new Map<string, TopologyCableEdge>();
  for (const c of savedCables) {
    cableMap.set(c.id, structuredClone(c));
  }
  const upsertCable = (c: TopologyCableEdge) => {
    if (!cableMap.has(c.id)) {
      cableMap.set(c.id, c);
    }
  };

  // WAN Uplink circuit(s) wired to WAN interface(s)
  if (wanInterfaces.length > 0) {
    wanInterfaces.forEach((wanIf, idx) => {
      const wanId = slugId('wan', wanIf.name || `wan-${idx}`);
      const dev = wanIf.device || wanIf.name;
      upsertDiscoveredNode({
        id: wanId,
        kind: 'wan',
        label: `WAN Uplink (${wanIf.name})`,
        hostRef: wanIf.name,
        layer: 'physical',
        managed: false,
        position: { x: 40, y: 80 + idx * 160 },
        ports: [{ id: wanIf.name, name: wanIf.name, kind: 'wan-uplink', vlanIds: [], planned: false }],
        metadata: { type: wanIf.type, subnet: wanIf.ipv4Address },
      });
      upsertCable({
        id: `auto-wan-${wanIf.name}`,
        sourceNodeId: wanId,
        sourcePortId: wanIf.name,
        targetNodeId: localHostId,
        targetPortId: dev,
        layer: 'physical',
        medium: 'fiber-os2',
        status: 'installed',
        cableLabel: `ISP ${wanIf.name}`,
        vlanIds: [],
      });
    });
  }

  // Peer Axonwall Hosts (Vault, K3s/Storage, extra Edge, NAS)
  for (const peer of state?.topology?.peers ?? []) {
    const peerProbe = fabric?.peers.find((pp) => pp.peerId === peer.id);
    const ports: TopologyPortSpec[] = (peerProbe?.nics ?? []).map((n) => ({
      id: n.device,
      name: n.device,
      kind: 'physical-nic',
      speedMbps: n.speedMbps || undefined,
      mtu: n.mtu || undefined,
      vlanIds: [],
      subnetCidr: n.ipv4Addresses?.[0],
      planned: false,
    }));
    if (ports.length === 0) {
      ports.push({ id: 'eth0', name: 'eth0', kind: 'physical-nic', vlanIds: [], planned: !peerProbe?.reachable });
    }
    const kindMap: Record<string, TopologyCanvasNode['kind']> = {
      'edge-ngfw': 'edge-ngfw',
      'k3s-storage': 'k3s-node',
      vault: 'vault',
      nas: 'nas',
      satellite: 'satellite',
      generic: 'generic-host',
    };
    upsertDiscoveredNode({
      id: slugId('peer', peer.id),
      kind: kindMap[peer.role] || 'generic-host',
      label: peer.name,
      hostRef: peer.id,
      layer: 'physical',
      managed: true,
      position: { x: 1020, y: 120 },
      ports,
      metadata: { apiUrl: peer.apiUrl, role: peer.role, site: peer.site, rack: peer.rack, peerId: peer.id },
    });
  }

  // Fleet Satellites
  for (const sat of state?.fleet?.nodes ?? []) {
    const satId = slugId('sat', sat.id);
    upsertDiscoveredNode({
      id: satId,
      kind: sat.role === 'edge-ngfw' ? 'edge-ngfw' : 'satellite',
      label: sat.name || sat.id,
      hostRef: sat.id,
      layer: 'physical',
      managed: true,
      position: { x: 1020, y: 340 },
      ports: [
        { id: sat.wanInterface || 'eth0', name: sat.wanInterface || 'eth0', kind: 'wan-uplink', vlanIds: [], planned: false },
        { id: 'wg0', name: 'wg0', kind: 'tunnel', vlanIds: [], subnetCidr: sat.wireguard?.tunnelIp, planned: false },
      ],
      metadata: { fleetId: sat.id, role: sat.role, status: sat.status, ip: sat.ip },
    });
  }

  // VLANs & WireGuard Overlays
  for (const vlan of state?.vlans ?? []) {
    const vlanNodeId = slugId('vlan', String(vlan.tag));
    const vlanIf = vlan.vlanInterface || `${vlan.parentInterface}.${vlan.tag}`;
    upsertDiscoveredNode({
      id: vlanNodeId,
      kind: 'vlan',
      label: `VLAN ${vlan.tag} (${vlan.description || vlanIf})`,
      hostRef: vlanIf,
      layer: 'l2-l3',
      managed: true,
      position: { x: 700, y: 100 },
      ports: [{ id: vlanIf, name: vlanIf, kind: 'vlan-if', vlanIds: [vlan.tag], planned: false }],
      metadata: { vlanTag: vlan.tag, parentInterface: vlan.parentInterface },
    });
    upsertCable({
      id: `auto-vlan-${vlan.tag}`,
      sourceNodeId: localHostId,
      sourcePortId: vlan.parentInterface,
      targetNodeId: vlanNodeId,
      targetPortId: vlanIf,
      layer: 'l2-l3',
      medium: 'vlan-trunk',
      status: 'virtual',
      cableLabel: `802.1Q ${vlan.tag}`,
      vlanIds: [vlan.tag],
    });
  }

  if (state?.wireguard?.enabled) {
    const wgId = 'vpn-wireguard';
    upsertDiscoveredNode({
      id: wgId,
      kind: 'vpn-overlay',
      label: `WireGuard :${state.wireguard.listenPort}`,
      hostRef: 'wg0',
      layer: 'vpn',
      managed: true,
      position: { x: 700, y: 280 },
      ports: [{ id: 'wg0', name: 'wg0', kind: 'tunnel', vlanIds: [], subnetCidr: state.wireguard.address, planned: false }],
      metadata: { listenPort: state.wireguard.listenPort, peersCount: state.wireguard.peers?.length ?? 0 },
    });
    upsertCable({
      id: 'auto-wg-local',
      sourceNodeId: localHostId,
      sourcePortId: localPorts[0]!.id,
      targetNodeId: wgId,
      targetPortId: 'wg0',
      layer: 'vpn',
      medium: 'wireguard',
      status: 'virtual',
      cableLabel: 'WG Overlay',
      vlanIds: [],
    });
  }

  // LibreNMS Discovered Switches/Devices + LLDP/CDP/xDP Links
  if (fabric?.librenms?.available) {
    for (const dev of fabric.librenms.devices) {
      const hostName = dev.sysName || dev.hostname;
      if (!hostName || hostName === localHostName) continue;
      // Check if matched by an existing host/peer node label
      const matchedNode = Array.from(nodeMap.values()).find(
        (n) => n.label.toLowerCase() === hostName.toLowerCase() || (n.hostRef && n.hostRef.toLowerCase() === hostName.toLowerCase()),
      );
      if (matchedNode) continue;

      const devPorts: TopologyPortSpec[] = fabric.librenms.ports
        .filter((p) => (p.deviceHost || '').toLowerCase() === dev.hostname.toLowerCase())
        .slice(0, 8)
        .map((p) => ({
          id: p.ifName,
          name: p.ifName,
          kind: 'switch-port',
          speedMbps: p.ifSpeedBps ? Math.round(p.ifSpeedBps / 1_000_000) : undefined,
          mtu: p.ifMtu || undefined,
          vlanIds: p.ifVlan ? [Number.parseInt(p.ifVlan, 10)].filter((v) => Number.isFinite(v) && v >= 1) : [],
          planned: false,
        }));
      upsertDiscoveredNode({
        id: slugId('lnms-sw', hostName),
        kind: 'switch',
        label: hostName,
        hostRef: dev.hostname,
        layer: 'physical',
        managed: false,
        position: { x: 700, y: 420 },
        ports: devPorts.length > 0 ? devPorts : [{ id: 'mgmt', name: 'mgmt', kind: 'switch-port', vlanIds: [], planned: false }],
        metadata: { os: dev.os, hardware: dev.hardware, ip: dev.ip, source: 'librenms' },
      });
    }
  }

  // Kubernetes Nodes, Ingresses/CRDs, Services, Workloads, PVCs
  if (fabric?.local?.k3s) {
    const k3s = fabric.local.k3s;
    const svcIdMap = new Map<string, { nodeId: string; portId: string }>();

    for (const kn of k3s.nodes) {
      upsertDiscoveredNode({
        id: slugId('k3s-node', kn.name),
        kind: 'k3s-node',
        label: `K3s ${kn.name}`,
        hostRef: kn.name,
        layer: 'k3s',
        managed: true,
        position: { x: 1020, y: 520 },
        ports: [{ id: 'cni', name: kn.internalIp || 'flannel', kind: 'physical-nic', vlanIds: [], planned: false }],
        metadata: { roles: kn.roles, status: kn.status, unschedulable: kn.unschedulable, nodeName: kn.name },
      });
    }

    for (const svc of k3s.services) {
      if (svc.namespace === 'kube-system' && svc.name === 'kube-dns') continue;
      const nid = slugId('k3s-svc', `${svc.namespace}-${svc.name}`);
      const pName = String(svc.ports?.[0] ?? 80);
      svcIdMap.set(`${svc.namespace}/${svc.name}`, { nodeId: nid, portId: pName });
      upsertDiscoveredNode({
        id: nid,
        kind: 'k3s-service',
        label: `${svc.name} (${svc.namespace})`,
        hostRef: svc.name,
        layer: 'k3s',
        managed: true,
        position: { x: 1640, y: 120 },
        ports: [{ id: pName, name: `${svc.type || 'ClusterIP'}:${pName}`, kind: 'service', vlanIds: [], planned: false }],
        metadata: { namespace: svc.namespace, name: svc.name, clusterIp: svc.clusterIp, readyEndpoints: svc.readyEndpoints },
      });
    }

    for (const ing of k3s.ingresses) {
      const nid = slugId('k3s-ing', `${ing.kind}-${ing.namespace}-${ing.name}`);
      const isCrd = ing.kind !== 'Ingress';
      upsertDiscoveredNode({
        id: nid,
        kind: isCrd ? 'k3s-crd' : 'k3s-ingress',
        label: `${ing.kind}: ${ing.name}`,
        hostRef: ing.name,
        layer: 'k3s',
        managed: true,
        position: { x: 1330, y: 120 },
        ports: [{ id: 'http', name: ing.hosts?.[0] || ing.namespace, kind: 'ingress', vlanIds: [], planned: false }],
        metadata: { namespace: ing.namespace, name: ing.name, kind: ing.kind, hosts: ing.hosts },
      });
      for (const b of ing.backendServices) {
        const target = svcIdMap.get(`${ing.namespace}/${b.name}`);
        if (target) {
          upsertCable({
            id: `auto-k3s-ing-${nid}-${target.nodeId}`,
            sourceNodeId: nid,
            sourcePortId: 'http',
            targetNodeId: target.nodeId,
            targetPortId: target.portId,
            layer: 'k3s',
            medium: 'k3s-route',
            status: 'virtual',
            cableLabel: `:${b.port || 80}`,
            vlanIds: [],
          });
        }
      }
    }

    for (const wl of k3s.workloads.slice(0, 24)) {
      const nid = slugId('k3s-wl', `${wl.namespace}-${wl.name}`);
      upsertDiscoveredNode({
        id: nid,
        kind: 'k3s-workload',
        label: `${wl.kind}: ${wl.name}`,
        hostRef: wl.name,
        layer: 'k3s',
        managed: true,
        position: { x: 1960, y: 120 },
        ports: [{ id: 'pods', name: `${wl.readyReplicas}/${wl.desiredReplicas}`, kind: 'generic', vlanIds: [], planned: false }],
        metadata: { namespace: wl.namespace, name: wl.name, kind: wl.kind, replicas: wl.desiredReplicas },
      });
    }

    for (const pvc of k3s.pvcs.slice(0, 16)) {
      const nid = slugId('k3s-pvc', `${pvc.namespace}-${pvc.name}`);
      upsertDiscoveredNode({
        id: nid,
        kind: 'k3s-pvc',
        label: `PVC: ${pvc.name}`,
        hostRef: pvc.name,
        layer: 'k3s',
        managed: true,
        position: { x: 1960, y: 420 },
        ports: [{ id: 'vol', name: pvc.capacity || 'vol', kind: 'storage', vlanIds: [], planned: false }],
        metadata: { namespace: pvc.namespace, name: pvc.name, storageClass: pvc.storageClass, bound: pvc.bound },
      });
    }
  }

  // KVM VMs & LXC Containers (Virt layer)
  for (const vm of fabric?.local?.vms ?? []) {
    const nid = slugId('vm', String(vm.vmid));
    upsertDiscoveredNode({
      id: nid,
      kind: 'kvm-vm',
      label: `VM ${vm.vmid}: ${vm.name}`,
      hostRef: String(vm.vmid),
      layer: 'virt',
      managed: true,
      position: { x: 1330, y: 520 },
      ports: [{ id: 'virtio0', name: 'virtio0', kind: 'virtual-nic', vlanIds: [], planned: false }],
      metadata: { vmid: vm.vmid, status: vm.status },
    });
  }
  for (const ct of fabric?.local?.containers ?? []) {
    const nid = slugId('ct', String(ct.ctid));
    upsertDiscoveredNode({
      id: nid,
      kind: 'lxc-container',
      label: `LXC ${ct.ctid}: ${ct.name}`,
      hostRef: String(ct.ctid),
      layer: 'virt',
      managed: true,
      position: { x: 1330, y: 660 },
      ports: [{ id: 'eth0', name: 'eth0', kind: 'virtual-nic', vlanIds: [], subnetCidr: ct.ipAddress, planned: false }],
      metadata: { ctid: ct.ctid, status: ct.status },
    });
  }

  const allNodes = Array.from(nodeMap.values());
  // Only run auto-layout on nodes that have never been placed (position == 0,0 and not in savedPositions)
  const laidOut = autoLayoutTopologyNodes(allNodes).map((n) => ({
    ...n,
    position: savedPositions.get(n.id) ?? n.position,
  }));

  return {
    nodes: laidOut,
    cables: Array.from(cableMap.values()),
  };
}
