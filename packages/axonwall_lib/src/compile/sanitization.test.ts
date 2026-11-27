import { describe, it, expect } from 'vitest';
import { compileUnbound } from './unbound/index.js';
import { compileTrafficShaper } from './tc/index.js';
import { compileSnmpd } from './snmp/index.js';
import { compileNutUps } from './nut/index.js';
import { compileFreeRadiusClients } from './freeradius/index.js';
import { compileSuricata } from './suricata/index.js';
import { compileCrowdSec } from './crowdsec/index.js';
import { compileKeepalived, compileConntrackd } from './ha/index.js';
import { compileLibvirtDomainXml, compileLxcContainer, compileCloudInit } from './virt/index.js';
import { compileZfsPoolCommand, compileSmbConf, compileCloudSyncCommands } from './nas/index.js';
import { compileAcme } from './acme/index.js';
import { compileIpsec } from './ipsec/index.js';
import { generateClientOvpnProfile } from './openvpn/index.js';
import { compileBpfLsmGuardC, compileRkhunterConfig } from './rootkit/index.js';
import { compileNftables } from './nft/index.js';
import { parseVyosTokens } from '../import/vyos/index.js';
import { DesiredStateSchema } from '../schemas/index.js';
import { findPluginById, isPluginAllowed, isPluginEnabled } from '../plugins/index.js';

describe('Compiler Input Sanitization & Security Hardening', () => {
  describe('Unbound DNS Compiler', () => {
    it('sanitizes CRLF and quote injection in host overrides, blocklists, and upstreams', () => {
      const res = compileUnbound({
        enabled: true,
        listenPort: 53,
        dnssec: true,
        dotEnabled: true,
        dotUpstreams: [
          '1.1.1.1@853#cloudflare-dns.com\nmalicious-directive: yes\r\n',
        ],
        hostOverrides: [
          {
            hostname: 'router\ninjected-config: "true"',
            domain: 'local\nserver: "bad"',
            ip: '192.168.1.1\ninjected',
            description: 'bad override',
          },
        ],
        blocklist: {
          enabled: true,
          feeds: [],
          whitelist: ['safe.com\nlocal-zone: "evil.com" transparent'],
          blacklist: ['ads.com\nlocal-zone: "evil2.com" always_null'],
          action: 'always_null',
        },
      }, {
        enabled: true,
        magicDnsDomain: 'magic.internal\ninjected: yes',
      } as any);

      // Verify no raw unescaped newlines or injected payloads inside directives
      expect(res.unboundConfig).not.toContain('injected-config');
      expect(res.unboundConfig).not.toContain('malicious-directive');
      expect(res.unboundConfig).not.toContain('evil.com" transparent');
      expect(res.unboundConfig).not.toContain('evil2.com" always_null');
      expect(res.unboundConfig).not.toContain('magic.internal\ninjected');
      expect(res.unboundConfig).toContain('local-data: "router.local. IN A 192.168.1.1"');
      expect(res.unboundConfig).toContain('local-zone: "safe.com." transparent');
      expect(res.unboundConfig).toContain('local-zone: "ads.com." always_null');
      expect(res.unboundConfig).toContain('forward-addr: 1.1.1.1@853#cloudflare-dns.com');
      expect(res.unboundConfig).toContain('local-zone: "magic.internal." transparent');
    });
  });

  describe('Traffic Control (TC) Compiler', () => {
    it('sanitizes interface names and prevents shell command injection', () => {
      const res = compileTrafficShaper({
        enabled: true,
        interfaces: [
          {
            interface: 'eth0; rm -rf / #',
            uploadBandwidthMbps: 100,
            downloadBandwidthMbps: 200,
            scheduler: 'cake',
            cakeDiffserv: 'diffserv4; reboot' as any,
            cakeAckFilter: true,
            enabled: true,
            queues: [],
          },
        ],
      });

      expect(res.shScript).not.toContain('; rm -rf /');
      expect(res.shScript).not.toContain('; reboot');
      expect(res.shScript).toContain('eth0rm-rf');
      expect(res.shScript).toContain('diffserv4');
    });
  });

  describe('SNMPd Compiler', () => {
    it('sanitizes community, sysLocation, and sysContact against newline injection', () => {
      const conf = compileSnmpd({
        enabled: true,
        version: 'v2c',
        community: 'public\nrocommunity evil-comm default\r\n',
        sysLocation: 'Server Room 1\nagentAddress udp:16161',
        sysContact: 'admin@axonwall.local\nexec badScript /bin/sh',
        listenPort: 161,
      });

      expect(conf).not.toContain('rocommunity evil-comm');
      expect(conf).not.toContain('agentAddress udp:16161');
      expect(conf).not.toContain('exec badScript');
      expect(conf).toContain('rocommunity public default');
      expect(conf).toContain('sysLocation Server Room 1');
      expect(conf).toContain('sysContact admin@axonwall.local');
    });
  });

  describe('NUT UPS Compiler', () => {
    it('prevents section escape and directive injection in ups.conf', () => {
      const res = compileNutUps({
        enabled: true,
        name: 'ups1]\n[evil_ups]\ndriver = evil\n[',
        driver: 'usbhid-ups\nmalicious = true',
        port: 'auto\nshutdown = now',
        shutdownBatteryPct: 20,
        lowBatteryRuntimeSec: 300,
      });

      expect(res.upsConf).not.toContain('[evil_ups]');
      expect(res.upsConf).not.toContain('malicious = true');
      expect(res.upsConf).not.toContain('shutdown = now');
      expect(res.upsConf).toContain('[ups1]');
      expect(res.upsConf).toContain('driver = usbhid-ups');
      expect(res.upsConf).toContain('port = auto');
    });
  });

  describe('FreeRADIUS Compiler', () => {
    it('sanitizes client name, IP address, and escapes quotes/newlines in secret', () => {
      const conf = compileFreeRadiusClients({
        enabled: true,
        authPort: 1812,
        acctPort: 1813,
        ldapSync: false,
        clients: [
          {
            name: 'ap-floor1 } client evil {',
            ipAddress: '192.168.10.50\n}',
            secret: 'testing"secret\nsecret = hacked',
          },
        ],
      });

      expect(conf).not.toContain('client evil {');
      expect(conf).not.toContain('secret = hacked');
      expect(conf).toContain('client ap-floor1 {');
      expect(conf).toContain('ipaddr = 192.168.10.50');
      expect(conf).toContain('secret = "testing\\"secret"');
    });
  });

  describe('Suricata Compiler', () => {
    it('sanitizes homeNet CIDRs and interface names against YAML/nftables injection', () => {
      const res = compileSuricata({
        enabled: true,
        mode: 'ips',
        interfaces: ['eth0"; drop; #'],
        nfqueueFailOpen: true,
        nfqueueBypass: true,
        ruleSources: [],
        homeNet: ['192.168.1.0/24\n  malicious_yaml: true'],
      });

      expect(res.suricataYaml).not.toContain('malicious_yaml');
      expect(res.suricataYaml).toContain('HOME_NET: "[192.168.1.0/24]"');
      expect(res.nftRules[0]).not.toContain('"; drop; #');
      expect(res.nftRules[0]).toContain('iifname "eth0"');
    });
  });

  describe('CrowdSec Compiler', () => {
    it('sanitizes remediationSetName and LAPI credentials', () => {
      const res = compileCrowdSec({
        enabled: true,
        remediationSetName: 'bad-set-name; drop; #',
        lapiUrl: 'http://127.0.0.1:8080/\ninjected: yaml',
        apiKey: 'key123"malicious\ninjected_key',
        action: 'drop',
        logBanned: false,
      });

      expect(res.bouncerYaml).not.toContain('injected: yaml');
      expect(res.bouncerYaml).not.toContain('injected_key');
      expect(res.bouncerYaml).not.toContain('key123"malicious');
      expect(res.bouncerYaml).toContain('set: badsetname');
      expect(res.bouncerYaml).toContain('api_url: http://127.0.0.1:8080/');
      expect(res.bouncerYaml).toContain('api_key: key123malicious');
      expect(res.nftSetDefinition).toContain('set badsetname {');
      expect(res.nftRule).toContain('ip saddr @badsetname drop');
    });
  });

  describe('High Availability (Keepalived & Conntrackd) Compilers', () => {
    it('sanitizes hostname, vrrp instance fields, and conntrack parameters', () => {
      const keepalived = compileKeepalived({
        enabled: true,
        nodeRole: 'master',
        peerAddress: '192.168.1.2',
        peerPort: 2966,
        vrrpInstances: [
          {
            name: 'VI_WAN\n} evil {',
            vrid: 51,
            interface: 'eth0\n  injected',
            priority: 150,
            virtualIps: ['192.168.1.254/24\n  1.2.3.4'],
            authPassword: 'pass\nword',
          },
        ],
        conntrackSync: {
          enabled: true,
          interface: 'eth0',
          protocol: 'unicast',
          peerAddress: '192.168.1.2',
          port: 3780,
        },
        sqliteSync: {
          enabled: false,
          mode: 'direct_stream',
          databases: [],
          syncIntervalSeconds: 5,
          listenPort: 9876,
          transport: 'token-http',
          requireSignedPayloads: false,
        },
        syncSections: {
          interfaces: false,
          firewall: true,
          dhcp: true,
          dns: true,
          aliases: true,
          vpn: true,
          sqlite: true,
        },
        maintenanceMode: false,
      }, 'router\ninjected_global');

      expect(keepalived).not.toContain('injected_global');
      expect(keepalived).not.toContain('} evil {');
      expect(keepalived).not.toContain('pass\nword');
      expect(keepalived).toContain('router_id router');
      expect(keepalived).toContain('vrrp_instance VI_WAN {');
      expect(keepalived).toContain('interface eth0');
      expect(keepalived).toContain('auth_pass pass');
      expect(keepalived).toContain('192.168.1.254/24');

      const conntrackd = compileConntrackd({
        enabled: true,
        nodeRole: 'master',
        peerAddress: '192.168.1.2',
        peerPort: 2966,
        vrrpInstances: [],
        conntrackSync: {
          enabled: true,
          interface: 'eth0\ninjected',
          protocol: 'unicast',
          peerAddress: '192.168.1.2\n  malicious',
          port: 3780,
          filterIgnoreIps: ['10.0.0.1\n  injected'],
        },
        sqliteSync: {
          enabled: false,
          mode: 'direct_stream',
          databases: [],
          syncIntervalSeconds: 5,
          listenPort: 9876,
          transport: 'token-http',
          requireSignedPayloads: false,
        },
        syncSections: {
          interfaces: false,
          firewall: true,
          dhcp: true,
          dns: true,
          aliases: true,
          vpn: true,
          sqlite: true,
        },
        maintenanceMode: false,
      }, '127.0.0.1\ninjected');

      expect(conntrackd).not.toContain('malicious');
      expect(conntrackd).not.toContain('injected');
      expect(conntrackd).toContain('Interface eth0');
      expect(conntrackd).toContain('IPv4_Destination_Address 192.168.1.2');
      expect(conntrackd).toContain('IPv4_address 10.0.0.1');
    });
  });

  describe('Phase 2A.4 Deep-Dive Hardening Regressions', () => {
    it('escapes XML attributes in Libvirt XML and sanitizes LXC header + Cloud-Init keys', () => {
      const xml = compileLibvirtDomainXml({
        vmid: 105,
        name: "vm'\"<>",
        osType: 'linux',
        bios: 'seabios',
        sockets: 1,
        cores: 2,
        cpuType: 'host',
        memoryMb: 1024,
        balloonMinMb: 0,
        disks: [{ name: 'd0', pool: 'tank', sizeGb: 10, zvol: '/dev/zvol/tank/disk0', bus: 'virtio', cache: 'none', discard: false, readOnly: false, backup: true, iopsReadLimit: 0, iopsWriteLimit: 0 }],
        nics: [{ mac: "52:54:00:00:00:01' <evil/>", bridge: "br0'><foo/>", model: 'virtio', firewall: true, rateLimitMbps: 0 }],
        virtioFsShares: [{ hostPath: '/mnt/tank/data', tag: "tag'<>", readOnly: false }],
        pciPassthrough: [],
        usbPassthrough: [],
        agent: false,
        autostart: false,
        haManaged: false,
        enabled: true,
        cloudInit: {
          user: 'op: bad',
          sshAuthorizedKeys: ['ssh-ed25519 AAAA\nruncmd: [id]'],
          ipConfig: 'dhcp',
          nameservers: [],
        },
      } as any);
      expect(xml).not.toContain("<evil/>");
      expect(xml).not.toContain("'><foo/>");
      expect(xml).toContain('&apos;');

      const ct = compileLxcContainer({
        ctid: 205,
        hostname: 'ct-safe\nlxc.hook.pre-start = /bin/sh',
        template: 'debian',
        unprivileged: true,
        cores: 1,
        memoryMb: 512,
        swapMb: 256,
        rootfsPool: 'tank',
        rootfsSizeGb: 8,
        features: [],
        nics: [],
        mountPoints: [],
        enabled: true,
      } as any);
      expect(ct.lxcConfig).not.toContain('\nlxc.hook.pre-start');

      const ci = compileCloudInit({
        vmid: 105,
        name: 'vm105',
        cloudInit: {
          user: 'admin',
          sshAuthorizedKeys: ['ssh-ed25519 AAAA key: injected'],
          ipConfig: 'dhcp',
          nameservers: [],
        },
      } as any);
      expect(ci?.userDataYaml).toContain('"ssh-ed25519 AAAA key: injected"');
    });

    it('blocks command/INI injection in ZFS, Samba, and CloudSync compilers', () => {
      expect(() =>
        compileZfsPoolCommand({ name: 'tank; rm -rf /', dataDisks: ['/dev/sda'], topology: 'stripe' } as any),
      ).toThrow();
      expect(() =>
        compileSmbConf({ enabled: true, smbShares: [{ name: 'global', path: '/tmp', enabled: true }] } as any),
      ).toThrow();
      const smb = compileSmbConf({
        enabled: true,
        workgroup: 'WORKGROUP\\',
        smbShares: [],
      } as any);
      expect(smb).toContain('workgroup = WORKGROUP\n');
      const syncCmds = compileCloudSyncCommands({
        enabled: true,
        cloudSyncTasks: [
          { enabled: true, provider: 's3', remoteBucket: "bkt'$(id)", localPath: '/mnt/tank/data', direction: 'push', transferMode: 'sync', bandwidthLimitMbps: 0 },
        ],
      } as any);
      expect(syncCmds[0]).toContain("'s3:bkt'\\''$(id)'");
    });

    it('fixes plugin privilege direction, read/write aliases, and explicit disabled flags', () => {
      const haproxy = findPluginById('haproxy')!;
      expect(isPluginAllowed(haproxy, ['system.config.read'])).toBe(false);
      expect(isPluginAllowed(haproxy, ['system.config.write'])).toBe(true);
      expect(isPluginAllowed(haproxy, ['services', 'system'])).toBe(true);
      expect(isPluginAllowed(haproxy, ['services.haproxy.read', 'system.certificates.read'])).toBe(false);

      const eluvixOff = DesiredStateSchema.parse({
        eluvix: { enabled: false },
        plugins: [{ id: 'eluvix', enabled: true }],
      });
      expect(isPluginEnabled('eluvix', eluvixOff)).toBe(false);

      const staleSvc = DesiredStateSchema.parse({
        haproxy: { enabled: true },
        plugins: [{ id: 'haproxy', enabled: false }],
      });
      expect(isPluginEnabled('haproxy', staleSvc)).toBe(false);
    });

    it('requires ct state established before nft flowtable offload', () => {
      const state = DesiredStateSchema.parse({
        interfaces: [
          { name: 'wan', device: 'eth0', role: 'wan', enabled: true },
          { name: 'lan', device: 'eth1', role: 'lan', enabled: true },
        ],
        system: { flowtableOffload: true },
      });
      const nft = compileNftables(state);
      expect(nft.nftScript).toContain('meta l4proto { tcp, udp } ct state established flow add @ft_fastpath');
    });

    it('single-quotes ACME domains, rejects malicious IPsec/OpenVPN inputs, guards VyOS parser, and fixes rootkit C comments + cron', () => {
      const acme = compileAcme({
        enabled: true,
        accounts: [],
        certificates: [
          { name: 'wc', domain: '*.example.com', altNames: [], challengeType: 'dns-01', dnsProvider: 'cloudflare', deployServices: ['webgui', 'evil\necho pwn' as any], autoRenew: true, renewDaysBeforeExpiry: 30, status: 'pending' },
        ],
        internalCAs: [],
      });
      expect(acme.renewScript).toContain("-d '*.example.com'");
      expect(acme.deployHooks[0].content).not.toContain('echo pwn');

      expect(() =>
        compileIpsec({
          enabled: true,
          tunnels: [{ name: 't1', enabled: true, remoteAddress: '1.2.3.4 } evil {', localAddress: '%any', localTs: ['0.0.0.0/0'], remoteTs: ['0.0.0.0/0'], ikeProposals: ['aes256-sha256'], espProposals: ['aes256-sha256'], authMethod: 'psk', dpdDelay: 30, dpdAction: 'restart', routeBased: false, xfrmInterfaceId: 1, description: '' }],
        }),
      ).toThrow();

      expect(() =>
        generateClientOvpnProfile({
          serverHost: 'vpn.example.com',
          serverPort: 1194,
          caCert: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n<script>bad</script>',
        }),
      ).toThrow();

      expect(() => parseVyosTokens(['__proto__', '{', 'polluted', 'true', ';', '}'])).toThrow(/Forbidden VyOS/);

      const lsmC = compileBpfLsmGuardC();
      expect(lsmC).toContain('//   - /usr/sbin/cryptsetup (ALLOW_FLAG_AF_ALG_AEAD)');
      expect(lsmC).not.toMatch(/^\s*\*   -/m);

      expect(() =>
        compileRkhunterConfig({ hostDefense: { scheduledScanCron: '0 3 * *\n0' } } as any),
      ).toThrow();
    });
  });
});
