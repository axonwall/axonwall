import { describe, it, expect } from 'vitest';
import { compileUnbound } from './unbound/index.js';
import { compileTrafficShaper } from './tc/index.js';
import { compileSnmpd } from './snmp/index.js';
import { compileNutUps } from './nut/index.js';
import { compileFreeRadiusClients } from './freeradius/index.js';
import { compileSuricata } from './suricata/index.js';
import { compileCrowdSec } from './crowdsec/index.js';
import { compileKeepalived, compileConntrackd } from './ha/index.js';

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
});
