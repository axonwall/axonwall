import type { DnsConfig } from '../../schemas/index.js';

export interface UnboundCompileResult {
  unboundConfig: string;
}

export function compileUnbound(dns: DnsConfig): UnboundCompileResult {
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

  return {
    unboundConfig: lines.join('\n'),
  };
}
