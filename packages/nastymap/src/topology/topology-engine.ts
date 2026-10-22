import type {
  FilterOptions,
  NmapHost,
  NmapRun,
  TopologyGraph,
  TopologyLayoutType,
  TopologyLink,
  TopologyNode,
} from '../types/nmap';

export interface TopologyOptions {
  layout?: TopologyLayoutType;
  filter?: FilterOptions;
  width?: number;
  height?: number;
  centerOrigin?: boolean;
}

function getSubnetFromIp(ip: string): string {
  if (!ip || ip.includes(':')) return 'IPv6 / Other';
  const parts = ip.split('.');
  if (parts.length >= 3) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return 'Unknown Subnet';
}

function getOsColor(osFamily?: string): string {
  const fam = (osFamily || '').toLowerCase();
  if (fam.includes('linux') || fam.includes('ubuntu') || fam.includes('debian')) return '#22c55e'; // Green
  if (fam.includes('windows') || fam.includes('microsoft')) return '#0ea5e9'; // Cyan/Blue
  if (fam.includes('mac') || fam.includes('apple') || fam.includes('ios') || fam.includes('darwin')) return '#a855f7'; // Purple
  if (fam.includes('cisco') || fam.includes('router') || fam.includes('switch')) return '#f59e0b'; // Amber
  if (fam.includes('bsd')) return '#ef4444'; // Red
  if (fam.includes('android')) return '#10b981'; // Emerald
  return '#94a3b8'; // Slate/Gray
}

/**
 * Generate a full topology graph from an Nmap scan.
 */
export function generateTopology(scan: NmapRun, options: TopologyOptions = {}): TopologyGraph {
  const { width = 1200, height = 800 } = options;
  const nodesMap = new Map<string, TopologyNode>();
  const linksMap = new Map<string, TopologyLink>();
  const subnetsSet = new Set<string>();

  // 1. Create Scanner Origin Node
  const scannerNodeId = 'scanner-origin';
  const scannerNode: TopologyNode = {
    id: scannerNodeId,
    label: 'Nmap Scanner (Local)',
    ip: '127.0.0.1',
    hostname: 'nmap-scanner',
    nodeType: 'scanner',
    status: 'up',
    osFamily: 'Local Host',
    osName: 'Scanner Host',
    deviceType: 'security scanner',
    openPorts: [],
    openPortDetails: [],
    latencyMs: 0,
    hopsAway: 0,
    subnet: '127.0.0.0/8',
    x: width / 2,
    y: height / 2,
    radius: 26,
    color: '#6366f1', // Indigo
  };
  nodesMap.set(scannerNodeId, scannerNode);

  // 2. Iterate through all hosts in scan
  for (const host of scan.hosts) {
    const ip = host.ipv4 || host.ipv6 || host.id;
    const subnet = getSubnetFromIp(ip);
    subnetsSet.add(subnet);

    const openPorts = host.ports.filter((p) => p.state === 'open').map((p) => p.portid);
    const openPortDetails = host.ports.filter((p) => p.state === 'open');
    const hopsAway = host.distance || (host.trace?.hops ? host.trace.hops.length : 1);

    const hostNode: TopologyNode = {
      id: ip,
      label: host.primaryHostname || ip,
      ip,
      hostname: host.primaryHostname,
      nodeType: host.deviceType === 'router' ? 'router' : 'host',
      status: host.status.state === 'up' ? 'up' : 'down',
      osFamily: host.osFamily || 'Unknown',
      osName: host.primaryOs || 'Unknown OS',
      deviceType: host.deviceType || 'general purpose',
      openPorts,
      openPortDetails,
      latencyMs: host.latencyMs,
      hopsAway,
      subnet,
      hostRef: host,
      geolocation: host.geolocation,
      x: width / 2,
      y: height / 2,
      radius: Math.min(32, Math.max(16, 16 + openPorts.length * 1.5)),
      color: getOsColor(host.osFamily),
    };
    nodesMap.set(ip, hostNode);

    // Check if traceroute information exists
    if (host.trace && host.trace.hops && host.trace.hops.length > 0) {
      let previousNodeId = scannerNodeId;

      for (let i = 0; i < host.trace.hops.length; i++) {
        const hop = host.trace.hops[i];
        const hopIp = hop.ipaddr || `hop-${host.id}-${hop.ttl}`;
        const isTargetHost = i === host.trace.hops.length - 1 || hopIp === ip;

        let hopNodeId = hopIp;

        if (!isTargetHost) {
          // Intermediate router / hop node
          if (!nodesMap.has(hopIp)) {
            const hopSubnet = getSubnetFromIp(hopIp);
            subnetsSet.add(hopSubnet);

            const interNode: TopologyNode = {
              id: hopIp,
              label: hop.host || hopIp,
              ip: hopIp,
              hostname: hop.host,
              nodeType: 'intermediate_hop',
              status: 'up',
              osFamily: 'Router / Network Hop',
              osName: 'Intermediate Router',
              deviceType: 'router',
              openPorts: [],
              openPortDetails: [],
              latencyMs: hop.rtt,
              hopsAway: hop.ttl,
              subnet: hopSubnet,
              x: width / 2,
              y: height / 2,
              radius: 14,
              color: '#eab308', // Amber/yellow
            };
            nodesMap.set(hopIp, interNode);
          }
          hopNodeId = hopIp;
        } else {
          hopNodeId = ip;
        }

        // Add link from previousNodeId to current hopNodeId
        const linkKey = `${previousNodeId}->${hopNodeId}`;
        if (!linksMap.has(linkKey) && previousNodeId !== hopNodeId) {
          linksMap.set(linkKey, {
            id: linkKey,
            source: previousNodeId,
            target: hopNodeId,
            rtt: hop.rtt,
            ttl: hop.ttl,
            type: 'traceroute',
            label: hop.rtt !== undefined ? `${hop.rtt.toFixed(1)}ms` : undefined,
          });
        }

        previousNodeId = hopNodeId;
      }
    } else {
      // Fallback when no traceroute is present:
      // Connect scanner -> subnet gateway or directly to target host
      const linkKey = `${scannerNodeId}->${ip}`;
      if (!linksMap.has(linkKey)) {
        linksMap.set(linkKey, {
          id: linkKey,
          source: scannerNodeId,
          target: ip,
          rtt: host.latencyMs,
          type: 'direct',
          label: host.latencyMs !== undefined ? `${host.latencyMs.toFixed(1)}ms` : undefined,
        });
      }
    }
  }

  const nodes = Array.from(nodesMap.values());
  const links = Array.from(linksMap.values());
  const subnets = Array.from(subnetsSet);

  const graph: TopologyGraph = {
    nodes,
    links,
    scannerNode,
    subnets,
  };

  // Apply layout coordinates
  applyLayout(graph, options.layout || 'force', width, height);

  return graph;
}

/**
 * Filter topology nodes based on user filter criteria.
 */
export function filterTopology(graph: TopologyGraph, filter?: FilterOptions): {
  visibleNodeIds: Set<string>;
  visibleLinkIds: Set<string>;
} {
  const visibleNodeIds = new Set<string>();
  const visibleLinkIds = new Set<string>();

  // Scanner origin is always visible
  visibleNodeIds.add(graph.scannerNode.id);

  if (!filter) {
    graph.nodes.forEach((n) => visibleNodeIds.add(n.id));
    graph.links.forEach((l) => visibleLinkIds.add(l.id));
    return { visibleNodeIds, visibleLinkIds };
  }

  const query = (filter.searchQuery || '').trim().toLowerCase();

  for (const node of graph.nodes) {
    if (node.id === graph.scannerNode.id) continue;

    let matches = true;

    // Search query matches IP, hostname, label, OS, service, or port
    if (query) {
      const matchIp = node.ip.toLowerCase().includes(query);
      const matchLabel = node.label.toLowerCase().includes(query);
      const matchHostname = (node.hostname || '').toLowerCase().includes(query);
      const matchOs = node.osName.toLowerCase().includes(query) || node.osFamily.toLowerCase().includes(query);
      const matchService = node.openPortDetails.some((p) =>
        (p.service?.name || '').toLowerCase().includes(query) ||
        (p.service?.product || '').toLowerCase().includes(query)
      );
      const matchPort = node.openPorts.some((p) => String(p).includes(query));

      if (!matchIp && !matchLabel && !matchHostname && !matchOs && !matchService && !matchPort) {
        matches = false;
      }
    }

    // OS family filter
    if (matches && filter.osFamily && filter.osFamily !== 'all') {
      if (node.osFamily.toLowerCase() !== filter.osFamily.toLowerCase()) {
        matches = false;
      }
    }

    // Port filter (e.g. only hosts with port 22 or 80)
    if (matches && filter.portFilter && filter.portFilter.length > 0) {
      const hasRequiredPort = filter.portFilter.some((reqPort) => node.openPorts.includes(reqPort));
      if (!hasRequiredPort) matches = false;
    }

    // Only open ports filter
    if (matches && filter.onlyOpenPorts) {
      if (node.openPorts.length === 0 && node.nodeType === 'host') {
        matches = false;
      }
    }

    // Only up hosts
    if (matches && filter.onlyUpHosts) {
      if (node.status !== 'up') matches = false;
    }

    // Subnet filter
    if (matches && filter.subnetFilter && filter.subnetFilter !== 'all') {
      if (node.subnet !== filter.subnetFilter) matches = false;
    }

    // Max latency filter
    if (matches && filter.maxLatencyMs !== undefined) {
      if (node.latencyMs !== undefined && node.latencyMs > filter.maxLatencyMs) {
        matches = false;
      }
    }

    // Device type filter
    if (matches && filter.deviceType && filter.deviceType !== 'all') {
      if (node.deviceType.toLowerCase() !== filter.deviceType.toLowerCase()) {
        matches = false;
      }
    }

    if (matches) {
      visibleNodeIds.add(node.id);
    }
  }

  // Include intermediate hops that lead to visible target nodes so the route isn't severed
  for (const link of graph.links) {
    const sId = typeof link.source === 'string' ? link.source : (link.source as TopologyNode).id;
    const tId = typeof link.target === 'string' ? link.target : (link.target as TopologyNode).id;

    if (visibleNodeIds.has(sId) && visibleNodeIds.has(tId)) {
      visibleLinkIds.add(link.id);
    }
  }

  return { visibleNodeIds, visibleLinkIds };
}

/**
 * Apply layout coordinates to graph nodes.
 */
export function applyLayout(
  graph: TopologyGraph,
  layout: TopologyLayoutType,
  width: number,
  height: number
): void {
  const cx = width / 2;
  const cy = height / 2;

  switch (layout) {
    case 'traceroute':
      applyTracerouteHierarchyLayout(graph, width, height);
      break;

    case 'radial':
      applyRadialLayout(graph, cx, cy, Math.min(width, height) * 0.42);
      break;

    case 'subnet':
      applySubnetGridLayout(graph, width, height);
      break;

    case 'circular':
      applyCircularLayout(graph, cx, cy, Math.min(width, height) * 0.38);
      break;

    case 'force':
    default:
      applyForceLayoutInitialPositions(graph, cx, cy, width, height);
      break;
  }
}

function applyTracerouteHierarchyLayout(graph: TopologyGraph, width: number, height: number): void {
  // Group nodes by hop distance (TTL)
  const hopLayers = new Map<number, TopologyNode[]>();

  for (const node of graph.nodes) {
    const hop = node.id === graph.scannerNode.id ? 0 : Math.max(1, node.hopsAway || 1);
    if (!hopLayers.has(hop)) hopLayers.set(hop, []);
    hopLayers.get(hop)!.push(node);
  }

  const sortedHops = Array.from(hopLayers.keys()).sort((a, b) => a - b);
  const maxHop = sortedHops[sortedHops.length - 1] || 1;
  const paddingX = 80;
  const availableWidth = width - paddingX * 2;
  const layerStepX = maxHop > 0 ? availableWidth / maxHop : availableWidth;

  for (const hop of sortedHops) {
    const layerNodes = hopLayers.get(hop)!;
    const count = layerNodes.length;
    const paddingY = 80;
    const availableHeight = height - paddingY * 2;
    const stepY = count > 1 ? availableHeight / (count - 1) : 0;

    layerNodes.forEach((node, idx) => {
      node.x = paddingX + hop * layerStepX;
      node.y = count === 1 ? height / 2 : paddingY + idx * stepY;
    });
  }
}

function applyRadialLayout(graph: TopologyGraph, cx: number, cy: number, maxRadius: number): void {
  // Center is scanner
  graph.scannerNode.x = cx;
  graph.scannerNode.y = cy;

  // Group other nodes by hop distance
  const hopGroups = new Map<number, TopologyNode[]>();
  for (const node of graph.nodes) {
    if (node.id === graph.scannerNode.id) continue;
    const hop = Math.max(1, node.hopsAway || 1);
    if (!hopGroups.has(hop)) hopGroups.set(hop, []);
    hopGroups.get(hop)!.push(node);
  }

  const maxHop = Math.max(1, ...Array.from(hopGroups.keys()));
  const ringStep = maxRadius / maxHop;

  for (const [hop, groupNodes] of hopGroups.entries()) {
    const ringRadius = hop * ringStep;
    const count = groupNodes.length;
    const angleStep = (2 * Math.PI) / count;

    groupNodes.forEach((node, idx) => {
      const angle = idx * angleStep - Math.PI / 2;
      node.x = cx + ringRadius * Math.cos(angle);
      node.y = cy + ringRadius * Math.sin(angle);
    });
  }
}

function applyCircularLayout(graph: TopologyGraph, cx: number, cy: number, radius: number): void {
  graph.scannerNode.x = cx;
  graph.scannerNode.y = cy;

  const targetNodes = graph.nodes.filter((n) => n.id !== graph.scannerNode.id);
  const count = targetNodes.length;
  const angleStep = (2 * Math.PI) / count;

  targetNodes.forEach((node, idx) => {
    const angle = idx * angleStep - Math.PI / 2;
    node.x = cx + radius * Math.cos(angle);
    node.y = cy + radius * Math.sin(angle);
  });
}

function applySubnetGridLayout(graph: TopologyGraph, width: number, height: number): void {
  const subnetMap = new Map<string, TopologyNode[]>();
  for (const node of graph.nodes) {
    if (node.id === graph.scannerNode.id) continue;
    const sub = node.subnet || 'Other';
    if (!subnetMap.has(sub)) subnetMap.set(sub, []);
    subnetMap.get(sub)!.push(node);
  }

  const subnets = Array.from(subnetMap.keys());
  const numSubnets = subnets.length;
  const cols = Math.ceil(Math.sqrt(numSubnets));
  const rows = Math.ceil(numSubnets / cols);

  const cellWidth = width / cols;
  const cellHeight = height / rows;

  graph.scannerNode.x = width / 2;
  graph.scannerNode.y = 40;

  subnets.forEach((sub, subIdx) => {
    const col = subIdx % cols;
    const row = Math.floor(subIdx / cols);
    const subCenterX = col * cellWidth + cellWidth / 2;
    const subCenterY = row * cellHeight + cellHeight / 2 + 30;

    const group = subnetMap.get(sub)!;
    const count = group.length;
    const subRadius = Math.min(cellWidth, cellHeight) * 0.35;
    const angleStep = (2 * Math.PI) / count;

    group.forEach((node, idx) => {
      const angle = idx * angleStep;
      node.x = subCenterX + subRadius * Math.cos(angle);
      node.y = subCenterY + subRadius * Math.sin(angle);
    });
  });
}

function applyForceLayoutInitialPositions(
  graph: TopologyGraph,
  cx: number,
  cy: number,
  width: number,
  height: number
): void {
  graph.scannerNode.x = cx;
  graph.scannerNode.y = cy;

  const targetNodes = graph.nodes.filter((n) => n.id !== graph.scannerNode.id);
  const count = targetNodes.length;

  targetNodes.forEach((node, idx) => {
    const angle = (idx / count) * 2 * Math.PI;
    const dist = 120 + (node.hopsAway || 1) * 70 + (idx % 3) * 30;
    node.x = cx + Math.cos(angle) * dist;
    node.y = cy + Math.sin(angle) * dist;
  });
}

/**
 * Step the 2D Physics Force Simulation for smooth dynamic graph layout.
 */
export function stepPhysicsSimulation(
  graph: TopologyGraph,
  width: number,
  height: number,
  alpha: number = 0.3
): void {
  const nodes = graph.nodes;
  const links = graph.links;
  const cx = width / 2;
  const cy = height / 2;

  const nodeMap = new Map<string, TopologyNode>();
  for (const n of nodes) {
    nodeMap.set(n.id, n);
    n.vx = (n.vx || 0) * 0.85; // friction damping
    n.vy = (n.vy || 0) * 0.85;
  }

  // 1. Repulsion force between all node pairs (Coulomb force)
  for (let i = 0; i < nodes.length; i++) {
    const n1 = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const n2 = nodes[j];
      const dx = n2.x - n1.x;
      const dy = n2.y - n1.y;
      const distSq = dx * dx + dy * dy || 1;
      const dist = Math.sqrt(distSq);

      const minDistance = n1.radius + n2.radius + 35;
      const repulsionStrength = 1800;
      const force = (repulsionStrength / (distSq + 100)) * alpha;

      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      if (!n1.isPinned && n1.nodeType !== 'scanner') {
        n1.vx = (n1.vx || 0) - fx;
        n1.vy = (n1.vy || 0) - fy;
      }
      if (!n2.isPinned && n2.nodeType !== 'scanner') {
        n2.vx = (n2.vx || 0) + fx;
        n2.vy = (n2.vy || 0) + fy;
      }

      // Hard collision resolution
      if (dist < minDistance) {
        const overlap = (minDistance - dist) * 0.5 * alpha;
        const ox = (dx / dist) * overlap;
        const oy = (dy / dist) * overlap;
        if (!n1.isPinned && n1.nodeType !== 'scanner') {
          n1.x -= ox;
          n1.y -= oy;
        }
        if (!n2.isPinned && n2.nodeType !== 'scanner') {
          n2.x += ox;
          n2.y += oy;
        }
      }
    }
  }

  // 2. Link spring force (Hooke's law)
  for (const link of links) {
    const sId = typeof link.source === 'string' ? link.source : (link.source as TopologyNode).id;
    const tId = typeof link.target === 'string' ? link.target : (link.target as TopologyNode).id;

    const source = nodeMap.get(sId);
    const target = nodeMap.get(tId);
    if (!source || !target) continue;

    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;

    const desiredDist = 110;
    const springForce = (dist - desiredDist) * 0.04 * alpha;

    const fx = (dx / dist) * springForce;
    const fy = (dy / dist) * springForce;

    if (!source.isPinned && source.nodeType !== 'scanner') {
      source.vx = (source.vx || 0) + fx;
      source.vy = (source.vy || 0) + fy;
    }
    if (!target.isPinned && target.nodeType !== 'scanner') {
      target.vx = (target.vx || 0) - fx;
      target.vy = (target.vy || 0) - fy;
    }
  }

  // 3. Gravity towards center
  for (const n of nodes) {
    if (n.isPinned || n.nodeType === 'scanner') continue;
    const dx = cx - n.x;
    const dy = cy - n.y;
    const gravityForce = 0.008 * alpha;
    n.vx = (n.vx || 0) + dx * gravityForce;
    n.vy = (n.vy || 0) + dy * gravityForce;

    // Apply velocities
    n.x += n.vx || 0;
    n.y += n.vy || 0;

    // Bounds containment
    const pad = 40;
    n.x = Math.max(pad, Math.min(width - pad, n.x));
    n.y = Math.max(pad, Math.min(height - pad, n.y));
  }
}
