import { describe, it, expect } from 'vitest';
import {
  DesiredStateSchema,
  RosenpassConfigSchema,
  WireGuardConfigSchema,
  compileRosenpass,
  compileWireGuard,
  compileNftables,
  BUILTIN_PLUGINS,
  isPluginEnabled,
  serializeDesiredStateToYamlFiles,
  parseDesiredStateFromYamlFiles,
} from '../index.js';

describe('Rosenpass Post-Quantum Hybrid Dual-KEM Plugin', () => {
  it('registers rosenpass in BUILTIN_PLUGINS and evaluates isPluginEnabled', () => {
    const manifest = BUILTIN_PLUGINS.find((p) => p.id === 'rosenpass');
    expect(manifest).toBeDefined();
    expect(manifest?.category).toBe('extension');
    expect(manifest?.menuEntry?.path).toBe('/vpn/rosenpass');

    const disabledState = DesiredStateSchema.parse({});
    expect(isPluginEnabled('rosenpass', disabledState)).toBe(false);

    const enabledViaConfig = DesiredStateSchema.parse({
      rosenpass: { enabled: true },
    });
    expect(isPluginEnabled('rosenpass', enabledViaConfig)).toBe(true);

    const enabledViaPluginList = DesiredStateSchema.parse({
      plugins: [{ id: 'rosenpass', enabled: true }],
    });
    expect(isPluginEnabled('rosenpass', enabledViaPluginList)).toBe(true);
  });

  it('compiles Rosenpass TOML configuration and strips control/quote characters', () => {
    const cfg = RosenpassConfigSchema.parse({
      enabled: true,
      listenPort: 9999,
      listenAddresses: ['0.0.0.0:9999', '[::]:9999'],
      wgDevice: 'wg0',
      verbosity: 'Quiet',
      publicKeyPath: '/etc/rosenpass/pq.pk',
      secretKeyPath: '/etc/rosenpass/pq.sk',
      peers: [
        {
          name: 'beta-node',
          wgPeerPublicKey: 'PeerBetaCurve25519Base64PublicKeyHere000000=',
          endpoint: '203.0.113.20:9999',
          pqPublicKeyPath: '/etc/rosenpass/peers/beta-node-pq.pk',
          pqPublicKeySha256: '8f4e2b1c9a0d3f5e7a6b8c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f',
          wgDevice: 'wg0',
          enabled: true,
        },
      ],
    });

    const res = compileRosenpass(cfg);
    expect(res.configToml).toContain('public_key = "/etc/rosenpass/pq.pk"');
    expect(res.configToml).toContain('secret_key = "/etc/rosenpass/pq.sk"');
    expect(res.configToml).toContain('listen = ["0.0.0.0:9999", "[::]:9999"]');
    expect(res.configToml).toContain('verbosity = "Quiet"');
    expect(res.configToml).toContain('[[peers]]');
    expect(res.configToml).toContain('public_key = "/etc/rosenpass/peers/beta-node-pq.pk"');
    expect(res.configToml).toContain('endpoint = "203.0.113.20:9999"');
    expect(res.configToml).toContain('wg_device = "wg0"');
    expect(res.configToml).toContain('wg_peer = "PeerBetaCurve25519Base64PublicKeyHere000000="');
    expect(res.systemdUnit).toContain('ExecStart=/usr/bin/rosenpass exchange-config /etc/rosenpass/config.toml');
    expect(res.systemdUnit).toContain('MemoryDenyWriteExecute=true');
  });

  it('injects fail-closed PostUp /dev/urandom PSK seed into wg0.conf when failClosedBootGuard is enabled', () => {
    const wg = WireGuardConfigSchema.parse({
      enabled: true,
      address: '10.99.0.1/24',
      listenPort: 51820,
      privateKey: 'AlphaNodeCurve25519SecretKeyBase64Here00000=',
      peers: [
        {
          name: 'beta-node',
          publicKey: 'PeerBetaCurve25519Base64PublicKeyHere000000=',
          allowedIps: ['10.99.0.2/32'],
          endpoint: '203.0.113.20:51820',
          persistentKeepalive: 25,
          enabled: true,
        },
      ],
    });

    const rpEnabled = RosenpassConfigSchema.parse({
      enabled: true,
      failClosedBootGuard: true,
      peers: [
        {
          name: 'beta-node',
          wgPeerPublicKey: 'PeerBetaCurve25519Base64PublicKeyHere000000=',
          pqPublicKeyPath: '/etc/rosenpass/peers/beta-node-pq.pk',
          enabled: true,
        },
      ],
    });

    const compiledWithGuard = compileWireGuard(wg, rpEnabled);
    expect(compiledWithGuard.wgConfig).toContain(
      "PostUp = sh -c 'head -c 32 /dev/urandom | base64 | wg set %i peer PeerBetaCurve25519Base64PublicKeyHere000000= preshared-key /dev/stdin'",
    );

    const rpDisabledGuard = RosenpassConfigSchema.parse({
      ...rpEnabled,
      failClosedBootGuard: false,
    });
    const compiledWithoutGuard = compileWireGuard(wg, rpDisabledGuard);
    expect(compiledWithoutGuard.wgConfig).not.toContain('PostUp =');
  });

  it('opens UDP listenPort in nftables input chain and emits /etc/rosenpass/config.toml when enabled', () => {
    const state = DesiredStateSchema.parse({
      wireguard: {
        enabled: true,
        address: '10.99.0.1/24',
        listenPort: 51820,
        peers: [
          {
            name: 'beta-node',
            publicKey: 'PeerBetaCurve25519Base64PublicKeyHere000000=',
            allowedIps: ['10.99.0.2/32'],
            enabled: true,
          },
        ],
      },
      rosenpass: {
        enabled: true,
        listenPort: 9999,
        failClosedBootGuard: true,
        peers: [
          {
            name: 'beta-node',
            wgPeerPublicKey: 'PeerBetaCurve25519Base64PublicKeyHere000000=',
            endpoint: '203.0.113.20:9999',
            pqPublicKeyPath: '/etc/rosenpass/peers/beta-node-pq.pk',
            enabled: true,
          },
        ],
      },
    });

    const compiled = compileNftables(state);
    expect(compiled.nftScript).toContain('udp dport 9999 accept comment "rosenpass-pq-kem"');
    const rpFile = compiled.files.find((f) => f.path === '/etc/rosenpass/config.toml');
    expect(rpFile).toBeDefined();
    expect(rpFile?.fileMode).toBe(0o600);
    expect(rpFile?.content).toContain('wg_peer = "PeerBetaCurve25519Base64PublicKeyHere000000="');

    const wgFile = compiled.files.find((f) => f.path === '/etc/wireguard/wg0.conf');
    expect(wgFile).toBeDefined();
    expect(wgFile?.content).toContain("PostUp = sh -c 'head -c 32 /dev/urandom | base64 | wg set %i peer");
    expect(compiled.reloadServices).toContain('rosenpass');
  });

  it('round-trips rosenpass configuration through vpn.yaml domain files', () => {
    const state = DesiredStateSchema.parse({
      rosenpass: {
        enabled: true,
        listenPort: 9999,
        wgDevice: 'wg0',
        failClosedBootGuard: true,
        publicKeySha256: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
        peers: [
          {
            name: 'gamma-node',
            wgPeerPublicKey: 'PeerGammaCurve25519Base64PublicKeyHere00000=',
            endpoint: '198.51.100.42:9999',
            pqPublicKeyPath: '/etc/rosenpass/peers/gamma-node-pq.pk',
            enabled: true,
          },
        ],
      },
    });

    const yamlMap = serializeDesiredStateToYamlFiles(state);
    expect(yamlMap['vpn.yaml']).toContain('rosenpass:');
    expect(yamlMap['vpn.yaml']).toContain('gamma-node');

    const parsed = parseDesiredStateFromYamlFiles(yamlMap);
    expect(parsed.rosenpass?.enabled).toBe(true);
    expect(parsed.rosenpass?.listenPort).toBe(9999);
    expect(parsed.rosenpass?.peers).toHaveLength(1);
    expect(parsed.rosenpass?.peers[0]?.name).toBe('gamma-node');
  });
});
