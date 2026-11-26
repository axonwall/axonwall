import { describe, it, expect } from 'vitest';
import { DesiredStateSchema } from '../schemas/index.js';
import { compileHaProxy } from './haproxy/index.js';
import { compileNftables } from './nft/index.js';
import { parseDesiredStateFromYamlFiles, serializeDesiredStateToYamlFiles } from '../yaml/index.js';

function makeBaseState(overrides: Record<string, unknown> = {}) {
  return DesiredStateSchema.parse({
    version: 1,
    system: {
      hostname: 'axonwall-edge',
      domain: 'corp.example',
      dnsServers: ['1.1.1.1'],
      timezone: 'UTC',
      flowtableOffload: false,
      antiLockout: { enabled: true, interface: 'lan', ports: [22, 80, 443, 3000] },
    },
    interfaces: [
      { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, description: 'WAN', mtu: 1500 },
      {
        name: 'lan',
        device: 'eth1',
        type: 'static',
        enabled: true,
        description: 'LAN',
        ipv4Address: '192.168.10.1/24',
        mtu: 1500,
      },
    ],
    ...overrides,
  });
}

describe('Headscale WAN Invite Access & Port Knocking compilation', () => {
  it('leaves HAProxy and nftables clean when wanInvite is disabled', () => {
    const state = makeBaseState({
      headscale: { enabled: true, magicDnsDomain: 'tailnet.corp.example' },
    });
    const compiled = compileNftables(state);

    expect(compiled.nftScript).not.toContain('headscale_wan_invite');
    expect(compiled.nftScript).not.toContain('headscale_wan_window_ports');
    expect(compiled.files.some((f) => f.path === '/etc/haproxy/haproxy.cfg')).toBe(false);

    const cfgFile = compiled.files.find((f) => f.path === '/etc/axonwall/managed/headscale_wan_config.json');
    expect(cfgFile).toBeDefined();
    expect(JSON.parse(cfgFile!.content)).toMatchObject({ enabled: false });
  });

  it('compiles strict HAProxy path allowlist, SNI/Host pinning, header sanitization, and silent-drop', () => {
    const state = makeBaseState({
      headscale: {
        enabled: true,
        magicDnsDomain: 'tailnet.corp.example',
        wanInvite: {
          enabled: true,
          hostname: 'join.corp.example',
          bindPort: 8443,
          certName: 'join-acme',
          autoWindow: true,
          requirePin: true,
          allowedCidrs: [],
          exposeHeadscaleControl: false,
        },
      },
    });

    const compiled = compileNftables(state);
    const haproxyFile = compiled.files.find((f) => f.path === '/etc/haproxy/haproxy.cfg');
    expect(haproxyFile).toBeDefined();
    const cfg = haproxyFile!.content;

    expect(cfg).toContain('frontend fe_headscale_wan_invite');
    expect(cfg).toContain('bind *:8443 ssl crt /etc/axonwall/certs/join-acme.pem');
    expect(cfg).toContain('acl valid_sni ssl_fc_sni -i join.corp.example');
    expect(cfg).toContain('acl valid_host req.hdr(host),field(1,:) -i join.corp.example');
    expect(cfg).toContain('http-request silent-drop unless valid_sni valid_host');
    expect(cfg).toContain('http-request del-header X-Forwarded-For');
    expect(cfg).toContain('http-request set-header X-Real-IP %[src]');
    expect(cfg).toContain('http-request silent-drop if bad_traversal or bad_encoded_dot or bad_encoded_slash');
    expect(cfg).toContain('acl allow_path_0 path_beg /invite/');
    expect(cfg).toContain('acl allow_path_5 path /api/v1/vpn/mesh/invites/preview');
    expect(cfg).toContain('acl allow_path_6 path /api/v1/vpn/mesh/invites/redeem');
    expect(cfg).toContain('http-request silent-drop unless { var(txn.path_allowed) -m int eq 1 }');
    expect(cfg).not.toContain('default_backend be_axonwall_invite_ui');
    expect(cfg).not.toContain('/login');
    expect(cfg).not.toContain('path_beg /vpn');
    expect(cfg).not.toContain('path /vpn');
    expect(cfg).not.toContain('/lobby');
    expect(cfg).not.toContain('/metrics');
    expect(compiled.reloadServices).toContain('haproxy');

    // Auto-window nftables sets & WAN/LAN separation
    expect(compiled.nftScript).toContain('set headscale_wan_window_ports');
    expect(compiled.nftScript).toContain('type inet_service;');
    expect(compiled.nftScript).toContain('chain headscale_wan_invite');
    expect(compiled.nftScript).toContain('tcp dport @headscale_wan_window_ports accept comment "headscale-wan-invite"');
    expect(compiled.nftScript).toContain('iifname "eth1" tcp dport 8443 accept comment "headscale-wan-invite-lan"');
    expect(compiled.nftScript).toContain('iifname "eth0" jump headscale_wan_invite');
  });

  it('optionally co-hosts Headscale client control-plane routes without exposing /admin or /metrics', () => {
    const state = makeBaseState({
      headscale: {
        enabled: true,
        wanInvite: {
          enabled: true,
          hostname: 'vpn.corp.example',
          bindPort: 8444,
          autoWindow: false,
          exposeHeadscaleControl: true,
        },
      },
    });

    const compiled = compileNftables(state);
    const cfg = compiled.files.find((f) => f.path === '/etc/haproxy/haproxy.cfg')!.content;
    expect(cfg).toContain('backend be_headscale_control');
    expect(cfg).toContain('server local_headscale 127.0.0.1:8080 check');
    expect(cfg).toContain('path /ts2021');
    expect(cfg).toContain('path_beg /noise');
    expect(cfg).toContain('path_beg /machine/');
    expect(cfg).toContain('path_beg /register/');
    expect(cfg).not.toContain('/metrics');
    expect(cfg).not.toContain('path_beg /admin');
    expect(cfg).not.toContain('path /admin');
    expect(compiled.nftScript).not.toContain('headscale_wan_window_ports');
    expect(compiled.nftScript).toContain('tcp dport 8444 accept comment "headscale-wan-invite"');
  });

  it('compiles reverse-ordered stateful UDP and TCP nftables port knocking rules + IPv4-only CIDR gates', () => {
    const udpState = makeBaseState({
      headscale: {
        enabled: true,
        wanInvite: {
          enabled: true,
          hostname: 'join.corp.example',
          bindPort: 8443,
          autoWindow: true,
          allowedCidrs: ['198.51.100.0/24'],
          portKnocking: {
            enabled: true,
            protocol: 'udp',
            sequence: [41821, 52913, 38477],
            stepTimeoutSec: 15,
            openDurationSec: 900,
          },
        },
      },
    });

    const udpCompiled = compileNftables(udpState);
    const nft = udpCompiled.nftScript;

    expect(nft).toContain('set headscale_wan_allowed_v4');
    expect(nft).toContain('198.51.100.0/24');
    expect(nft).toContain('ip saddr != @headscale_wan_allowed_v4 return');
    expect(nft).toContain('meta nfproto ipv6 return');
    expect(nft).toContain('set headscale_knock_s1_v4');
    expect(nft).toContain('set headscale_knock_s2_v4');
    expect(nft).toContain('set headscale_knock_allow_v4');
    expect(nft).toContain('set headscale_knock_allow_v6');

    // Stage 3 unlock MUST precede stage 2, which MUST precede stage 1
    const unlockIdx = nft.indexOf('headscale-knock-unlock-v4');
    const s2Idx = nft.indexOf('headscale-knock-s2-v4');
    const s1Idx = nft.indexOf('headscale-knock-s1-v4');
    expect(unlockIdx).toBeGreaterThan(-1);
    expect(s2Idx).toBeGreaterThan(unlockIdx);
    expect(s1Idx).toBeGreaterThan(s2Idx);

    expect(nft).toContain(
      'ip saddr @headscale_knock_allow_v4 tcp dport @headscale_wan_window_ports accept comment "headscale-wan-invite-knock-v4"',
    );

    // TCP SYN-only knock matching
    const tcpState = makeBaseState({
      headscale: {
        enabled: true,
        wanInvite: {
          enabled: true,
          hostname: 'join.corp.example',
          bindPort: 8443,
          autoWindow: true,
          portKnocking: {
            enabled: true,
            protocol: 'tcp',
            sequence: [20111, 30222],
            stepTimeoutSec: 10,
            openDurationSec: 600,
          },
        },
      },
    });
    const tcpCompiled = compileNftables(tcpState);
    expect(tcpCompiled.nftScript).toContain('tcp flags & (fin|syn|rst|ack) == syn tcp dport 30222');
    expect(tcpCompiled.nftScript).toContain('tcp flags & (fin|syn|rst|ack) == syn tcp dport 20111');
  });

  it('supports Host Mode rulesets when core-firewall is disabled', () => {
    const state = makeBaseState({
      capabilities: { firewallEnabled: false, nasEnabled: false, k3sEnabled: false, virtEnabled: false },
      headscale: {
        enabled: true,
        wanInvite: {
          enabled: true,
          hostname: 'join.host.example',
          bindPort: 8443,
          autoWindow: true,
          portKnocking: {
            enabled: true,
            protocol: 'udp',
            sequence: [41821, 52913, 38477],
            stepTimeoutSec: 15,
            openDurationSec: 900,
          },
        },
      },
    });

    const compiled = compileNftables(state);
    expect(compiled.nftScript).toContain('Axonwall Host-Mode Appliance Ruleset');
    expect(compiled.nftScript).toContain('set headscale_wan_window_ports');
    expect(compiled.nftScript).toContain('chain headscale_wan_invite');
    expect(compiled.nftScript).toContain('iifname "eth0" jump headscale_wan_invite');
  });

  it('sanitizes malicious HAProxy inputs, warns on port collisions & invalid knock ports, and round-trips via vpn.yaml', () => {
    const rawHaproxy = compileHaProxy({
      enabled: true,
      mode: 'http',
      frontends: [
        {
          name: 'fe_test',
          bindPort: 8443,
          ssl: true,
          certName: '../bad\ncert',
          defaultBackend: 'be_ui',
          strictHost: 'https://join.example.com:8443/path\ninjected',
          pathRules: [
            { matchType: 'beg', path: '/../../etc/passwd', methods: ['GET'], backend: 'be_ui' },
            { matchType: 'exact', path: '/invite/abc', methods: ['GET'], backend: 'be_ui' },
          ],
          silentDropUnmatched: true,
          sanitizeProxyHeaders: true,
        },
      ],
      backends: [
        { name: 'be_ui', mode: 'http', balance: 'roundrobin', servers: [{ name: 'ui', address: '127.0.0.1', port: 3000, check: true }] },
      ],
    });
    expect(rawHaproxy).toContain('acl valid_sni ssl_fc_sni -i join.example.com');
    expect(rawHaproxy).not.toContain('../etc/passwd');
    expect(rawHaproxy).not.toContain('\ninjected');

    // Port collision + bindPort inside knock sequence warnings
    const collidedState = makeBaseState({
      haproxy: {
        enabled: true,
        mode: 'http',
        frontends: [{ name: 'fe_existing', bindPort: 8443, ssl: true, certName: 'hub', defaultBackend: 'be_app' }],
        backends: [
          {
            name: 'be_app',
            mode: 'http',
            balance: 'roundrobin',
            servers: [{ name: 'app', address: '10.0.0.2', port: 8080, check: true }],
          },
        ],
      },
      headscale: {
        enabled: true,
        wanInvite: {
          enabled: true,
          hostname: 'join.corp.example',
          bindPort: 8443,
          allowedCidrs: ['not-an-ip'],
          portKnocking: {
            enabled: true,
            protocol: 'udp',
            sequence: [8443, 52913],
            stepTimeoutSec: 15,
            openDurationSec: 900,
          },
        },
      },
    });
    const res = compileNftables(collidedState);
    expect(res.warnings.some((w) => w.includes('Port 8443 is already in use'))).toBe(true);
    expect(res.warnings.some((w) => w.includes('cannot include the HTTPS invite port'))).toBe(true);
    expect(res.warnings.some((w) => w.includes('Ignored invalid Headscale WAN invite allowedCidr'))).toBe(true);
    // Invalid allowedCidrs only => fails closed with bare return
    expect(res.nftScript).toContain('  chain headscale_wan_invite {\n    return\n');

    // YAML vpn.yaml round-trip
    const yamlState = makeBaseState({
      headscale: {
        enabled: true,
        magicDnsDomain: 'tailnet.corp.example',
        serverUrl: 'https://hs.corp.example',
        wanInvite: {
          enabled: true,
          hostname: 'join.corp.example',
          bindPort: 8443,
          certName: 'hub',
          autoWindow: true,
          requirePin: true,
          allowedCidrs: ['203.0.113.0/24'],
          exposeHeadscaleControl: false,
          portKnocking: {
            enabled: true,
            protocol: 'udp',
            sequence: [41821, 52913, 38477],
            stepTimeoutSec: 15,
            openDurationSec: 900,
          },
        },
      },
    });
    const yamlFiles = serializeDesiredStateToYamlFiles(yamlState);
    expect(yamlFiles['vpn.yaml']).toContain('wanInvite:');
    expect(yamlFiles['vpn.yaml']).toContain('portKnocking:');
    const parsed = parseDesiredStateFromYamlFiles(yamlFiles);
    expect(parsed.headscale?.wanInvite?.enabled).toBe(true);
    expect(parsed.headscale?.wanInvite?.requirePin).toBe(true);
    expect(parsed.headscale?.wanInvite?.portKnocking?.sequence).toEqual([41821, 52913, 38477]);
  });
});
