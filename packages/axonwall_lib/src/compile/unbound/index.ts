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
  lines.push(`  auto-trust-anchor-file: "${dns.dnssec ? '/var/lib/unbound/root.key' : ''}"`);
  lines.push('');

  // Host Overrides
  if (dns.hostOverrides.length > 0) {
    lines.push('  # Local Host Overrides');
    for (const override of dns.hostOverrides) {
      const fqdn = `${override.hostname}.${override.domain}.`;
      lines.push(`  local-data: "${fqdn} IN A ${override.ip}"`);
      // Also generate PTR reverse record if needed
      lines.push(`  local-data-ptr: "${override.ip} ${fqdn}"`);
    }
    lines.push('');
  }

  // DNS Blocklist / RPZ (AdBlock & Malware Sinkholing)
  if (dns.blocklist && dns.blocklist.enabled) {
    const action = dns.blocklist.action || 'always_null';
    lines.push('  # AdBlock and Malware Domain Sinkholing');

    // Whitelisted domains are set to transparent so they are resolved normally
    for (const domain of dns.blocklist.whitelist) {
      lines.push(`  local-zone: "${domain}." transparent`);
    }

    // Blacklisted domains are sinkholed
    for (const domain of dns.blocklist.blacklist) {
      lines.push(`  local-zone: "${domain}." ${action}`);
    }
    lines.push('');
  }

  // Upstream Forwarding (DNS-over-TLS or standard)
  if (dns.dotEnabled && dns.dotUpstreams.length > 0) {
    lines.push('forward-zone:');
    lines.push('  name: "."');
    lines.push('  forward-tls-upstream: yes');
    for (const upstream of dns.dotUpstreams) {
      lines.push(`  forward-addr: ${upstream}`);
    }
  } else if (dns.dotUpstreams.length > 0) {
    lines.push('forward-zone:');
    lines.push('  name: "."');
    for (const upstream of dns.dotUpstreams) {
      const plain = upstream.split('@')[0];
      lines.push(`  forward-addr: ${plain}`);
    }
  }

  // Headscale MagicDNS integration
  if (headscale?.enabled && headscale.magicDnsDomain) {
    lines.push('');
    lines.push('# Headscale MagicDNS Forwarding');
    lines.push('server:');
    lines.push(`  local-zone: "${headscale.magicDnsDomain}." transparent`);
    lines.push('forward-zone:');
    lines.push(`  name: "${headscale.magicDnsDomain}."`);
    lines.push('  forward-addr: 127.0.0.1@5353'); // Assuming Headscale is configured to listen for DNS on 5353, or unbound can route to tailscale's local DNS
  }

  return {
    unboundConfig: lines.join('\n'),
  };
}
