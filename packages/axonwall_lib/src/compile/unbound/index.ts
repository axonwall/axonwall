import type { DnsConfig, HeadscaleConfig } from '../../schemas/index.js';
export * from './sinkhole.js';

export interface UnboundCompileResult {
  unboundConfig: string;
}

export function compileUnbound(dns: DnsConfig, headscale?: HeadscaleConfig): UnboundCompileResult {
  const lines: string[] = [];

  lines.push('# Axonwall Unbound DNS Configuration');
  lines.push('# Generated automatically by @axonwall/lib');
  lines.push('');
  lines.push('server:');
  lines.push(`  port: ${dns.listenPort}`);
  lines.push('  interface: 0.0.0.0');
  lines.push('  interface: ::0');
  lines.push('  access-control: 127.0.0.0/8 allow');
  lines.push('  access-control: 10.0.0.0/8 allow');
  lines.push('  access-control: 172.16.0.0/12 allow');
  lines.push('  access-control: 192.168.0.0/16 allow');
  lines.push('  access-control: fc00::/7 allow');
  lines.push('  access-control: fe80::/10 allow');
  lines.push('');
  lines.push('  hide-identity: yes');
  lines.push('  hide-version: yes');
  lines.push('  harden-glue: yes');
  lines.push('  harden-dnssec-stripped: yes');
  if (dns.dnssec) {
    lines.push('  auto-trust-anchor-file: "/var/lib/unbound/root.key"');
  }
  lines.push('');

  // Host Overrides
  if (dns.hostOverrides.length > 0) {
    lines.push('  # Local Host Overrides');
    for (const override of dns.hostOverrides) {
      const safeHostname = override.hostname.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '');
      const safeDomain = override.domain.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '');
      const safeIp = override.ip.split(/[\r\n]/)[0].trim().replace(/[^a-fA-F0-9:.]/g, '');
      if (!safeHostname || !safeDomain || !safeIp) continue;
      const fqdn = `${safeHostname}.${safeDomain}.`;
      const recordType = safeIp.includes(':') ? 'IN AAAA' : 'IN A';
      lines.push(`  local-data: "${fqdn} ${recordType} ${safeIp}"`);
      // Also generate PTR reverse record if needed
      lines.push(`  local-data-ptr: "${safeIp} ${fqdn}"`);
    }
    lines.push('');
  }

  // DNS Blocklist / RPZ (AdBlock & Malware Sinkholing)
  if (dns.blocklist && dns.blocklist.enabled) {
    const rawAction = (dns.blocklist.action || 'always_null').split(/[\r\n]/)[0].trim();
    const action = rawAction === 'always_nxdomain' ? 'always_nxdomain' : 'always_null';
    lines.push('  # AdBlock and Malware Domain Sinkholing');

    // Whitelisted domains are set to transparent so they are resolved normally
    for (const domain of dns.blocklist.whitelist) {
      const safeDomain = domain.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '');
      if (safeDomain) {
        lines.push(`  local-zone: "${safeDomain}." transparent`);
      }
    }

    // Blacklisted domains are sinkholed
    for (const domain of dns.blocklist.blacklist) {
      const safeDomain = domain.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '');
      if (safeDomain) {
        lines.push(`  local-zone: "${safeDomain}." ${action}`);
      }
    }
    lines.push('');
  }

  // Upstream Forwarding (DNS-over-TLS or standard)
  if (dns.dotEnabled && dns.dotUpstreams.length > 0) {
    lines.push('forward-zone:');
    lines.push('  name: "."');
    lines.push('  forward-tls-upstream: yes');
    for (const upstream of dns.dotUpstreams) {
      const safeUpstream = upstream.split(/[\r\n]/)[0].trim().replace(/[\r\n\s"';]/g, '');
      if (safeUpstream) {
        lines.push(`  forward-addr: ${safeUpstream}`);
      }
    }
  } else if (dns.dotUpstreams.length > 0) {
    lines.push('forward-zone:');
    lines.push('  name: "."');
    for (const upstream of dns.dotUpstreams) {
      const plain = upstream.split(/[\r\n]/)[0].split('@')[0].trim().replace(/[\r\n\s"';]/g, '');
      if (plain) {
        lines.push(`  forward-addr: ${plain}`);
      }
    }
  }

  // Headscale MagicDNS integration
  if (headscale?.enabled && headscale.magicDnsDomain) {
    const safeMagicDomain = headscale.magicDnsDomain.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '');
    if (safeMagicDomain) {
      lines.push('');
      lines.push('# Headscale MagicDNS Forwarding');
      lines.push('server:');
      lines.push(`  local-zone: "${safeMagicDomain}." transparent`);
      lines.push('forward-zone:');
      lines.push(`  name: "${safeMagicDomain}."`);
      lines.push('  forward-addr: 127.0.0.1@5353');
    }
  }

  return {
    unboundConfig: lines.join('\n'),
  };
}
