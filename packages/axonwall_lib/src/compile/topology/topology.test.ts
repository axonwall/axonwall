import { describe, expect, it } from 'vitest';
import {
  DesiredStateSchema,
  compileLldpdConfig,
  compileNftables,
  enablePluginWithDependencies,
  isPluginEnabled,
  evaluateFabricHealth,
  analyzeTopologyDiagnostics,
  traceFabricPath,
  exportCableCutSheet,
  buildFabricApplyPlan,
  type TopologyCanvasNode,
  type TopologyCableEdge,
  type FabricProbeSnapshot,
} from '../../index.js';
import { serializeDesiredStateToYamlFiles, validateYamlConfigFiles } from '../../yaml/index.js';

describe('Topology Studio Plugin, LLDP Guardrails, Health Evaluator & Diagnostics', () => {
  it('enables topology-studio standalone and strictly excludes WAN interfaces from lldpd config', () => {
    const base = DesiredStateSchema.parse({
      interfaces: [
        { name: 'wan', device: 'eth0', role: 'wan', enabled: true, type: 'dhcp' },
        { name: 'wan2', device: 'eth3', role: 'wan', enabled: true, type: 'dhcp' },
        { name: 'lan', device: 'eth1', role: 'lan', enabled: true, type: 'static', ipv4Address: '10.10.0.1/24' },
        { name: 'storage', device: 'eth2', role: 'lan', enabled: true, type: 'static', ipv4Address: '10.20.0.1/24' },
      ],
      topology: {
        enabled: true,
        lldp: {
          enabled: true,
          excludeWan: true,
          // Even if an operator attempts to list WAN eth0 here, compiler must drop it!
          interfaces: ['eth0', 'eth1', 'eth2'],
        },
      },
    });
    const res = enablePluginWithDependencies('topology-studio', base);
    expect(isPluginEnabled('topology-studio', res.state)).toBe(true);

    const lldp = compileLldpdConfig(res.state);
    expect(lldp.enabled).toBe(true);
    expect(lldp.allowedInterfaces).toEqual(['eth1', 'eth2']);
    expect(lldp.excludedWanInterfaces).toEqual(['eth0', 'eth3']);
    expect(lldp.confContent).toContain('!eth0,!eth3,!wan*,eth1,eth2');
    expect(lldp.confContent).not.toMatch(/configure system interface pattern[^#\n]*,eth0\b/);
  });

  it('enforces strict green/yellow/red rules across physical cables, LLDP, MTU/VLAN mismatches, and K3s routes', () => {
    const nodes: TopologyCanvasNode[] = [
      {
        id: 'edge-1',
        kind: 'edge-ngfw',
        label: 'edge-fw',
        hostRef: 'edge-fw',
        layer: 'physical',
        managed: true,
        position: { x: 0, y: 0 },
        ports: [
          { id: 'eth1', name: 'eth1', kind: 'sfp', mtu: 9000, vlanIds: [10, 20], planned: false },
          { id: 'eth2', name: 'eth2', kind: 'physical-nic', mtu: 1500, vlanIds: [30], planned: false },
        ],
        metadata: {},
      },
      {
        id: 'sw-1',
        kind: 'switch',
        label: 'core-sw01',
        hostRef: 'core-sw01',
        layer: 'physical',
        managed: false,
        position: { x: 200, y: 0 },
        ports: [
          { id: 'swp1', name: 'Ethernet1', kind: 'switch-port', mtu: 9000, vlanIds: [20], planned: false },
          { id: 'swp2', name: 'Ethernet2', kind: 'switch-port', mtu: 9000, vlanIds: [30], planned: false },
          { id: 'swp3', name: 'Ethernet3', kind: 'switch-port', mtu: 1500, vlanIds: [40], planned: true },
        ],
        metadata: {},
      },
      {
        id: 'vault-1',
        kind: 'vault',
        label: 'vault-nas',
        hostRef: 'vault-nas',
        layer: 'physical',
        managed: true,
        position: { x: 400, y: 0 },
        ports: [
          { id: 'eth0', name: 'eth0', kind: 'physical-nic', mtu: 1500, vlanIds: [40], planned: false },
        ],
        metadata: {},
      },
      {
        id: 'ing-1',
        kind: 'k3s-ingress',
        label: 'web-ingress',
        hostRef: 'web-ingress',
        layer: 'k3s',
        managed: true,
        position: { x: 400, y: 200 },
        ports: [{ id: 'http', name: 'http', kind: 'ingress', vlanIds: [], planned: false }],
        metadata: { namespace: 'default' },
      },
      {
        id: 'svc-1',
        kind: 'k3s-service',
        label: 'web-svc',
        hostRef: 'web-svc',
        layer: 'k3s',
        managed: true,
        position: { x: 600, y: 200 },
        ports: [{ id: 'port', name: '80', kind: 'service', vlanIds: [], planned: false }],
        metadata: { namespace: 'default' },
      },
    ];

    const cables: TopologyCableEdge[] = [
      // Green: LLDP / LibreNMS verified end-to-end with matching MTU & overlapping VLAN 20
      {
        id: 'c-green',
        sourceNodeId: 'edge-1',
        sourcePortId: 'eth1',
        targetNodeId: 'sw-1',
        targetPortId: 'swp1',
        layer: 'physical',
        medium: 'fiber-om4',
        status: 'installed',
        vlanIds: [20],
        cableLabel: 'DAC-01',
      },
      // Red: MTU mismatch (1500 vs 9000)
      {
        id: 'c-red-mtu',
        sourceNodeId: 'edge-1',
        sourcePortId: 'eth2',
        targetNodeId: 'sw-1',
        targetPortId: 'swp2',
        layer: 'physical',
        medium: 'rj45-cat6a',
        status: 'installed',
        vlanIds: [30],
      },
      // Yellow: Planned physical cable (swp3 is planned)
      {
        id: 'c-yellow-planned',
        sourceNodeId: 'sw-1',
        sourcePortId: 'swp3',
        targetNodeId: 'vault-1',
        targetPortId: 'eth0',
        layer: 'physical',
        medium: 'rj45-cat6a',
        status: 'planned',
        vlanIds: [40],
        cableLabel: '=CMD()',
      },
      // K3s Ingress -> Service link: Red because svc has 0 ready endpoints
      {
        id: 'c-k3s',
        sourceNodeId: 'ing-1',
        sourcePortId: 'http',
        targetNodeId: 'svc-1',
        targetPortId: 'port',
        layer: 'k3s',
        medium: 'k3s-route',
        status: 'virtual',
        vlanIds: [],
      },
    ];

    const probe: FabricProbeSnapshot = {
      localHostId: 'edge-fw',
      nics: [
        {
          hostId: 'edge-fw',
          device: 'eth1',
          adminUp: true,
          carrierUp: true,
          speedMbps: 10000,
          mtu: 9000,
          lldpNeighbors: [{ chassisName: 'core-sw01', portId: 'Ethernet1' }],
        },
        {
          hostId: 'edge-fw',
          device: 'eth2',
          adminUp: true,
          carrierUp: true,
          speedMbps: 1000,
          mtu: 1500,
        },
      ],
      tunnels: [],
      gateways: [],
      peers: [],
      librenms: {
        available: true,
        devices: [{ hostname: 'core-sw01', status: true }],
        ports: [
          { deviceHost: 'core-sw01', ifName: 'Ethernet1', ifOperStatus: 'up', ifMtu: 9000 },
          { deviceHost: 'core-sw01', ifName: 'Ethernet2', ifOperStatus: 'up', ifMtu: 9000 },
        ],
        links: [
          { localDevice: 'edge-fw', localPort: 'eth1', remoteDevice: 'core-sw01', remotePort: 'Ethernet1', protocol: 'lldp', active: true },
        ],
        alerts: [],
      },
      k3s: {
        nodes: [{ name: 'edge-fw', status: 'Ready', roles: 'control-plane' }],
        ingresses: [
          { name: 'web-ingress', namespace: 'default', backendServices: [{ name: 'web-svc', port: 80 }], kind: 'Ingress' },
        ],
        services: [{ name: 'web-svc', namespace: 'default', readyEndpoints: 0 }],
        workloads: [],
        pvcs: [],
        networkPolicies: [{ kind: 'NetworkPolicy', name: 'allow-web', namespace: 'default' }],
      },
    };

    const health = evaluateFabricHealth(nodes, cables, probe);
    expect(health.cableHealth['c-green']?.status).toBe('green');
    expect(health.cableHealth['c-red-mtu']?.status).toBe('red');
    expect(health.cableHealth['c-red-mtu']?.reason).toContain('MTU mismatch');
    expect(health.cableHealth['c-yellow-planned']?.status).toBe('yellow');
    expect(health.portHealth['sw-1:swp3']?.status).toBe('yellow');
    expect(health.nodeHealth['ing-1']?.status).toBe('red');
    expect(health.cableHealth['c-k3s']?.status).toBe('red');

    const diags = analyzeTopologyDiagnostics(nodes, cables, health, probe);
    expect(diags.some((d) => d.code === 'MTU_MISMATCH' && d.quickFix?.actionType === 'align-cable-mtu')).toBe(true);
    expect(diags.some((d) => d.code === 'ORPHAN_INGRESS')).toBe(true);
    expect(diags.some((d) => d.code === 'SPOF_K3S_CONTROL')).toBe(true);

    const csv = exportCableCutSheet(nodes, cables, health, 'csv');
    expect(csv).toContain("'=CMD()"); // CSV formula injection neutralization
    expect(csv).toContain('DAC-01');

    const traced = traceFabricPath(
      nodes,
      cables,
      health,
      { nat: [{ type: 'port-forward', interface: 'wan', destination: '10.10.0.10', description: 'HTTP In', enabled: true }], rules: [] },
      'edge-1',
      'vault-1',
      probe,
    );
    expect(traced.hops).toHaveLength(3);
    expect(traced.overallHealth).toBe('yellow');
  });

  it('orders multi-target apply plan across validation, K3s/peers, and local edge last', () => {
    const localState = DesiredStateSchema.parse({ topology: { enabled: true } });
    const plan = buildFabricApplyPlan({
      localState,
      k3sEdits: [{ kind: 'Ingress', name: 'app-ing', namespace: 'prod' }],
      peerEdits: [{ peerId: 'vault-1', name: 'Vault', apiUrl: 'https://10.10.0.5:2966', state: localState }],
      confirmTimeoutSeconds: 180,
    });
    expect(plan.confirmTimeoutSeconds).toBe(180);
    expect(plan.phases).toHaveLength(3);
    expect(plan.phases[0]!.targets).toHaveLength(3);
    expect(plan.phases[1]!.targets.map((t) => t.targetType)).toEqual(['k3s', 'peer']);
    expect(plan.phases[2]!.targets.map((t) => t.targetType)).toEqual(['local']);
  });

  it('emits topology_config.json and round-trips inside topology.yaml', () => {
    const state = DesiredStateSchema.parse({
      topology: {
        enabled: true,
        lldp: { enabled: true, excludeWan: true, interfaces: ['eth1'] },
        peers: [{ id: 'vault-1', name: 'Vault Host', role: 'vault', apiUrl: 'https://10.10.0.50:2966', apiToken: 'peer-tok' }],
      },
      plugins: [{ id: 'topology-studio', enabled: true }],
    });
    const compiled = compileNftables(state);
    const managed = compiled.files.find((f) => f.path === '/etc/axonwall/managed/topology_config.json');
    expect(managed).toBeDefined();
    expect(managed?.fileMode).toBe(0o600);

    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    expect(yamlFiles['topology.yaml']).toContain('Vault Host');
    const validation = validateYamlConfigFiles(yamlFiles);
    expect(validation.valid).toBe(true);
    expect(validation.state?.topology?.peers).toHaveLength(1);
  });
});
