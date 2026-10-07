import { describe, expect, it } from 'vitest';
import { compileSuricata, parseEveAlert } from './suricata/index.js';
import { compileCaptivePortal, CaptiveSessionManager } from '../captive/index.js';
import { parseUrlTableFeed, computeSetDiff, resolveGeoIpPrefixes, resolveAsnPrefixes } from '../alias/index.js';
import { compileUnbound } from './unbound/index.js';
import { compileAcme } from './acme/index.js';
import { compileCrowdSec } from './crowdsec/index.js';

describe('Phase 3: Suricata IDS/IPS Compiler & EVE JSON Parser', () => {
  it('compiles Suricata 7.0 YAML in IPS mode with NFQUEUE bypass', () => {
    const res = compileSuricata({
      enabled: true,
      mode: 'ips',
      interfaces: ['wan'],
      nfqueueFailOpen: true,
      nfqueueBypass: true,
      ruleSources: [
        { name: 'ET Open', url: 'https://rules.emergingthreats.net/...', enabled: true },
      ],
      homeNet: ['192.168.100.0/24'],
    });

    expect(res.suricataYaml).toContain('suricata-version: "7.0"');
    expect(res.suricataYaml).toContain('HOME_NET: "[192.168.100.0/24]"');
    expect(res.suricataYaml).toContain('mode: accept');
    expect(res.suricataYaml).toContain('fail-open: yes');
    expect(res.suricataYaml).toContain('bypass: yes');

    expect(res.nftRules).toContain('iifname "wan" queue num 0-3 bypass comment "suricata-ips-inbound"');
  });

  it('parses Suricata EVE JSON alert events', () => {
    const jsonSample = JSON.stringify({
      timestamp: '2026-10-05T06:00:00.000000+0000',
      event_type: 'alert',
      src_ip: '198.51.100.4',
      src_port: 43210,
      dest_ip: '192.168.100.10',
      dest_port: 80,
      proto: 'TCP',
      alert: {
        action: 'blocked',
        gid: 1,
        signature_id: 2001219,
        rev: 20,
        signature: 'ET SCAN Potential SSH Scan',
        category: 'Attempted Information Leak',
        severity: 2,
      },
    });

    const alert = parseEveAlert(jsonSample);
    expect(alert).not.toBeNull();
    expect(alert?.signature).toBe('ET SCAN Potential SSH Scan');
    expect(alert?.severity).toBe(2);
    expect(alert?.srcIp).toBe('198.51.100.4');
    expect(alert?.action).toBe('blocked');
  });
});

describe('Phase 3: Captive Portal Engine & Session Manager', () => {
  it('compiles captive portal redirection and passthrough rules', () => {
    const res = compileCaptivePortal({
      enabled: true,
      zones: [
        {
          id: 'cp-guest',
          name: 'GuestWiFi',
          interface: 'wlan0',
          listenPort: 8999,
          authServers: ['ldap_internal'],
          sessionTimeoutMinutes: 480,
          idleTimeoutMinutes: 30,
          passThroughMacs: ['00:11:22:33:44:55'],
          passThroughIps: ['192.168.200.254'],
          enableBandwidthQuotas: true,
          downloadLimitKbps: 5000,
          uploadLimitKbps: 2000,
          enabled: true,
        },
      ],
    });

    expect(res.nftRules).toContain('iifname "wlan0" ether saddr 00:11:22:33:44:55 accept comment "captive-passthrough-mac"');
    expect(res.nftRules).toContain('iifname "wlan0" ip saddr 192.168.200.254 accept comment "captive-passthrough-ip"');
    expect(res.nftRules).toContain('iifname "wlan0" tcp dport 80 redirect to :8999 comment "captive-GuestWiFi-http"');
    expect(res.nftRules).toContain('iifname "wlan0" tcp dport 443 redirect to :8999 comment "captive-GuestWiFi-https"');
  });

  it('manages guest sessions with expiration checking', () => {
    const mgr = new CaptiveSessionManager();
    const zone = {
      name: 'GuestZone',
      interface: 'wlan0',
      listenPort: 8999,
      authServers: ['ldap_internal'],
      sessionTimeoutMinutes: 60,
      idleTimeoutMinutes: 15,
      passThroughMacs: [],
      passThroughIps: [],
      enableBandwidthQuotas: false,
      downloadLimitKbps: 10000,
      uploadLimitKbps: 5000,
      enabled: true,
    };

    const sess = mgr.createSession(zone, '192.168.200.45', 'aa:bb:cc:dd:ee:ff', 'john.doe');
    expect(mgr.isClientAuthenticated('192.168.200.45')).toBe(true);
    expect(mgr.getActiveSessions()).toHaveLength(1);

    mgr.terminateSession(sess.sessionId);
    expect(mgr.isClientAuthenticated('192.168.200.45')).toBe(false);
  });
});

describe('Phase 3: Dynamic Alias Refresher Engine', () => {
  it('parses URL Table feeds ignoring comments and invalid tokens', () => {
    const feed = `
      # Spamhaus DROP List
      ; Updated hourly
      198.51.100.0/24 ; comment
      203.0.113.50
      invalid-entry
      # 10.0.0.0/8
      192.0.2.1
    `;
    const ips = parseUrlTableFeed(feed);
    expect(ips).toContain('198.51.100.0/24');
    expect(ips).toContain('203.0.113.50');
    expect(ips).toContain('192.0.2.1');
    expect(ips).not.toContain('invalid-entry');
    expect(ips).not.toContain('10.0.0.0/8');
  });

  it('computes minimal incremental nftables set diffs', () => {
    const current = ['198.51.100.1', '198.51.100.2'];
    const fresh = ['198.51.100.2', '198.51.100.3'];

    const diff = computeSetDiff('axonwall', 'set_threats', current, fresh);
    expect(diff.toAdd).toEqual(['198.51.100.3']);
    expect(diff.toDelete).toEqual(['198.51.100.1']);
    expect(diff.nftStatements).toContain('delete element inet axonwall set_threats { 198.51.100.1 }');
    expect(diff.nftStatements).toContain('add element inet axonwall set_threats { 198.51.100.3 }');
  });

  it('resolves GeoIP countries and ASNs', () => {
    const usPrefixes = resolveGeoIpPrefixes('US');
    expect(usPrefixes.length).toBeGreaterThan(0);
    const googlePrefixes = resolveAsnPrefixes(15169);
    expect(googlePrefixes).toContain('8.8.8.0/24');
  });
});

describe('Phase 3: Unbound DNS Blocklist (RPZ AdBlock)', () => {
  it('compiles domain blocklists and honors whitelist transparent rules', () => {
    const res = compileUnbound({
      enabled: true,
      listenPort: 53,
      dnssec: true,
      dotEnabled: false,
      dotUpstreams: ['1.1.1.1'],
      hostOverrides: [],
      blocklist: {
        enabled: true,
        feeds: [],
        whitelist: ['safe-api.example.com'],
        blacklist: ['adtracker.evil.com', 'malware.bad.org'],
        action: 'always_null',
      },
    });

    expect(res.unboundConfig).toContain('local-zone: "safe-api.example.com." transparent');
    expect(res.unboundConfig).toContain('local-zone: "adtracker.evil.com." always_null');
    expect(res.unboundConfig).toContain('local-zone: "malware.bad.org." always_null');
  });
});

describe('Phase 3: ACME Client & CrowdSec Integration', () => {
  it('compiles ACME renewal scripts and service reload hooks', () => {
    const res = compileAcme({
      enabled: true,
      accounts: [
        {
          id: 'acme-acc',
          name: 'DefaultAccount',
          email: 'admin@axonwall.local',
          caDirectoryUrl: 'https://acme-v02.api.letsencrypt.org/directory',
          enabled: true,
        },
      ],
      certificates: [
        {
          id: 'cert-1',
          name: 'firewall-cert',
          domain: 'gw.axonwall.net',
          altNames: ['vpn.axonwall.net'],
          challengeType: 'http-01',
          autoRenew: true,
          renewDaysBeforeExpiry: 30,
          deployServices: ['webgui', 'openvpn'],
          status: 'valid',
        },
      ],
      internalCAs: [],
    });

    expect(res.renewScript).toContain('certbot certonly --webroot -w /var/www/acme-challenge');
    expect(res.renewScript).toContain('-d gw.axonwall.net -d vpn.axonwall.net');
    expect(res.hookScripts.webgui).toContain('systemctl reload-or-restart axonwall');
    expect(res.hookScripts.openvpn).toContain('systemctl reload-or-restart openvpn');
  });

  it('compiles CrowdSec bouncer configuration and native nftables set binding', () => {
    const res = compileCrowdSec({
      enabled: true,
      lapiUrl: 'http://127.0.0.1:8080/',
      apiKey: 'test-crowdsec-key-1234',
      remediationSetName: 'set_crowdsec_blacklists',
      action: 'drop',
      logBanned: true,
    });

    expect(res.bouncerYaml).toContain('api_url: http://127.0.0.1:8080/');
    expect(res.bouncerYaml).toContain('set: set_crowdsec_blacklists');
    expect(res.nftSetDefinition).toContain('set set_crowdsec_blacklists {');
    expect(res.nftRule).toContain('ip saddr @set_crowdsec_blacklists log prefix');
  });
});
