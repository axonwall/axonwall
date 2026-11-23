import type { Edge, Node } from '@xyflow/react';
import type {
  CableHealthResult,
  EndpointHealthResult,
  FabricHealthEvaluation,
  HealthTone,
} from '@axonwall/lib/compile/topology';
import type {
  TopologyCableEdge,
  TopologyCanvasNode,
  TopologyLayer,
} from '@axonwall/lib/schemas';

export type TopologyFilterLayer = 'all' | TopologyLayer;

export interface TopologyFlowNodeData extends Record<string, unknown> {
  model: TopologyCanvasNode;
  health?: EndpointHealthResult;
  portHealth?: Record<string, EndpointHealthResult>;
  activeAlertsCount?: number;
  isTraced?: boolean;
  onSelectPort?: (nodeId: string, portId: string) => void;
}

export interface TopologyFlowEdgeData extends Record<string, unknown> {
  model: TopologyCableEdge;
  health?: CableHealthResult;
  isTraced?: boolean;
}

export type TopologyFlowNode = Node<TopologyFlowNodeData, 'fabricNode'>;
export type TopologyFlowEdge = Edge<TopologyFlowEdgeData, 'fabricEdge'>;

export interface StagedK3sEdit {
  id: string;
  kind: string;
  name: string;
  namespace?: string;
  manifestYaml?: string;
  scaleReplicas?: number;
  nodeRoles?: string[];
  summary: string;
}

export interface StagedPeerEdit {
  peerId: string;
  name: string;
  summary: string;
  state: unknown;
}

export const HEALTH_TONE_CLASSES: Record<
  HealthTone,
  { dot: string; border: string; text: string; stroke: string; badgeBg: string }
> = {
  green: {
    dot: 'bg-emerald-400',
    border: 'border-emerald-500/50',
    text: 'text-emerald-300',
    stroke: '#10b981',
    badgeBg: 'bg-emerald-500/10',
  },
  yellow: {
    dot: 'bg-amber-400',
    border: 'border-amber-500/45',
    text: 'text-amber-300',
    stroke: '#f59e0b',
    badgeBg: 'bg-amber-500/10',
  },
  red: {
    dot: 'bg-rose-500',
    border: 'border-rose-500/65',
    text: 'text-rose-300',
    stroke: '#ef4444',
    badgeBg: 'bg-rose-500/15',
  },
};

export const NODE_KIND_CATALOG: Array<{
  kind: TopologyCanvasNode['kind'];
  label: string;
  layer: TopologyLayer;
  defaultPorts: TopologyCanvasNode['ports'];
}> = [
  {
    kind: 'wan',
    label: 'WAN / ISP Circuit',
    layer: 'physical',
    defaultPorts: [{ id: 'uplink', name: 'wan', kind: 'wan-uplink', vlanIds: [], planned: true }],
  },
  {
    kind: 'switch',
    label: 'Managed / Unmanaged Switch',
    layer: 'physical',
    defaultPorts: [
      { id: 'p1', name: 'Port-1', kind: 'switch-port', vlanIds: [], planned: true },
      { id: 'p2', name: 'Port-2', kind: 'switch-port', vlanIds: [], planned: true },
      { id: 'sfp1', name: 'SFP+1', kind: 'sfp', speedMbps: 10000, vlanIds: [], planned: true },
    ],
  },
  {
    kind: 'patch-panel',
    label: 'Patch Panel',
    layer: 'physical',
    defaultPorts: [
      { id: 'j1', name: 'Jack-01', kind: 'physical-nic', vlanIds: [], planned: true },
      { id: 'j2', name: 'Jack-02', kind: 'physical-nic', vlanIds: [], planned: true },
    ],
  },
  {
    kind: 'edge-ngfw',
    label: 'Edge NGFW',
    layer: 'physical',
    defaultPorts: [
      { id: 'eth0', name: 'eth0', kind: 'wan-uplink', vlanIds: [], planned: false },
      { id: 'eth1', name: 'eth1', kind: 'physical-nic', vlanIds: [], planned: false },
    ],
  },
  {
    kind: 'k3s-node',
    label: 'K3s / Storage Node',
    layer: 'k3s',
    defaultPorts: [{ id: 'eth0', name: 'eth0', kind: 'physical-nic', vlanIds: [], planned: false }],
  },
  {
    kind: 'vault',
    label: 'Vault Node',
    layer: 'physical',
    defaultPorts: [{ id: 'eth0', name: 'eth0', kind: 'physical-nic', vlanIds: [], planned: false }],
  },
  {
    kind: 'nas',
    label: 'ZFS Storage / NAS',
    layer: 'physical',
    defaultPorts: [{ id: 'sfp0', name: 'sfp0', kind: 'sfp', speedMbps: 10000, vlanIds: [], planned: false }],
  },
  {
    kind: 'satellite',
    label: 'Satellite Node',
    layer: 'physical',
    defaultPorts: [{ id: 'wg0', name: 'wg0', kind: 'tunnel', vlanIds: [], planned: false }],
  },
  {
    kind: 'generic-host',
    label: 'Generic Host / Server',
    layer: 'physical',
    defaultPorts: [{ id: 'eth0', name: 'eth0', kind: 'physical-nic', vlanIds: [], planned: true }],
  },
  {
    kind: 'vlan',
    label: '802.1Q VLAN / Subnet',
    layer: 'l2-l3',
    defaultPorts: [{ id: 'vlan', name: 'vlan', kind: 'vlan-if', vlanIds: [10], planned: false }],
  },
  {
    kind: 'vpn-overlay',
    label: 'WireGuard / Headscale / IPsec',
    layer: 'vpn',
    defaultPorts: [{ id: 'tun', name: 'tunnel', kind: 'tunnel', vlanIds: [], planned: false }],
  },
  {
    kind: 'k3s-ingress',
    label: 'K3s Ingress / ServiceLB',
    layer: 'k3s',
    defaultPorts: [{ id: 'in', name: '443/80', kind: 'ingress', vlanIds: [], planned: false }],
  },
  {
    kind: 'k3s-service',
    label: 'K3s Service',
    layer: 'k3s',
    defaultPorts: [{ id: 'svc', name: 'svc', kind: 'service', vlanIds: [], planned: false }],
  },
  {
    kind: 'k3s-workload',
    label: 'K3s Workload',
    layer: 'k3s',
    defaultPorts: [{ id: 'pod', name: 'pod', kind: 'generic', vlanIds: [], planned: false }],
  },
  {
    kind: 'k3s-pvc',
    label: 'OpenEBS ZFS PVC',
    layer: 'k3s',
    defaultPorts: [{ id: 'pvc', name: 'vol', kind: 'storage', vlanIds: [], planned: false }],
  },
  {
    kind: 'kvm-vm',
    label: 'KVM Virtual Machine',
    layer: 'virt',
    defaultPorts: [{ id: 'tap0', name: 'virtio0', kind: 'virtual-nic', vlanIds: [], planned: false }],
  },
  {
    kind: 'lxc-container',
    label: 'LXC Container',
    layer: 'virt',
    defaultPorts: [{ id: 'veth0', name: 'eth0', kind: 'virtual-nic', vlanIds: [], planned: false }],
  },
];

export type { FabricHealthEvaluation };
