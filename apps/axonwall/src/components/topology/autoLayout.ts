import type { TopologyCanvasNode } from '@axonwall/lib/schemas';

const TIER_COLUMN: Record<TopologyCanvasNode['kind'], number> = {
  wan: 0,
  'edge-ngfw': 1,
  haproxy: 2,
  'vpn-overlay': 2,
  vip: 2,
  switch: 2,
  'patch-panel': 2,
  vlan: 2,
  'bridge-bond': 2,
  vault: 3,
  nas: 3,
  satellite: 3,
  'generic-host': 3,
  'k3s-node': 3,
  'kvm-vm': 4,
  'lxc-container': 4,
  'k3s-ingress': 4,
  'k3s-crd': 4,
  'k3s-netpol': 4,
  'k3s-service': 5,
  'k3s-workload': 6,
  'k3s-pvc': 6,
};

/**
 * Deterministic left-to-right tiered fabric layout (WAN -> Edge -> Switches/L2/VPN -> Hosts/K3s -> Ingress -> Services -> Workloads/PVCs).
 */
export function autoLayoutTopologyNodes(nodes: TopologyCanvasNode[]): TopologyCanvasNode[] {
  const columns = new Map<number, TopologyCanvasNode[]>();
  for (const node of nodes) {
    const col = TIER_COLUMN[node.kind] ?? 3;
    const list = columns.get(col) ?? [];
    list.push(node);
    columns.set(col, list);
  }

  const colSpacing = 330;
  const rowBaseSpacing = 175;
  const positioned = new Map<string, { x: number; y: number }>();

  for (const [col, colNodes] of Array.from(columns.entries()).sort((a, b) => a[0] - b[0])) {
    let curY = 40;
    for (const node of colNodes) {
      positioned.set(node.id, { x: 40 + col * colSpacing, y: curY });
      const portCount = Math.max(1, node.ports?.length ?? 1);
      curY += rowBaseSpacing + Math.max(0, portCount - 2) * 26;
    }
  }

  return nodes.map((n) => ({
    ...n,
    position: positioned.get(n.id) ?? n.position,
  }));
}
