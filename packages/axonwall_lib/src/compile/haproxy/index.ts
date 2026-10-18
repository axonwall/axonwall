import type { HaProxyPluginConfig } from '../../schemas/index.js';

/**
 * Compiles HAProxy configuration (/etc/haproxy/haproxy.cfg).
 */
function safeIdentifier(str: string): string {
  return str.replace(/[^a-zA-Z0-9_-]/g, '_');
}

export function compileHaProxy(config: HaProxyPluginConfig): string {
  const lines: string[] = [];

  const safeConfigMode = safeIdentifier(config.mode);

  lines.push('# /etc/haproxy/haproxy.cfg - Managed by Axonwall HAProxy Plugin');
  lines.push('');
  lines.push('global');
  lines.push('    log /dev/log local0');
  lines.push('    log /dev/log local1 notice');
  lines.push('    chroot /var/lib/haproxy');
  lines.push('    user haproxy');
  lines.push('    group haproxy');
  lines.push('    daemon');
  lines.push('    stats socket /run/haproxy/admin.sock mode 660 level admin');
  lines.push('    stats timeout 30s');
  lines.push('    maxconn 4096');
  lines.push('    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384');
  lines.push('    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets');
  lines.push('');

  lines.push('defaults');
  lines.push('    log global');
  lines.push(`    mode ${safeConfigMode}`);
  lines.push('    option httplog');
  lines.push('    option dontlognull');
  lines.push('    timeout connect 5000ms');
  lines.push('    timeout client  50000ms');
  lines.push('    timeout server  50000ms');
  lines.push('');

  for (const fe of config.frontends) {
    const safeFeName = safeIdentifier(fe.name);
    lines.push(`frontend ${safeFeName}`);
    let bindLine = `    bind *:${fe.bindPort}`;
    if (fe.ssl && fe.certName) {
      const safeCert = safeIdentifier(fe.certName);
      bindLine += ` ssl crt /etc/axonwall/certs/${safeCert}.pem`;
    }
    lines.push(bindLine);
    lines.push(`    mode ${safeConfigMode}`);
    if (safeConfigMode === 'http') {
      lines.push('    option forwardfor');
      lines.push('    http-request set-header X-Forwarded-Proto https if { ssl_fc }');
    }
    lines.push(`    default_backend ${safeIdentifier(fe.defaultBackend)}`);
    lines.push('');
  }

  for (const be of config.backends) {
    const safeBeName = safeIdentifier(be.name);
    lines.push(`backend ${safeBeName}`);
    lines.push(`    mode ${safeIdentifier(be.mode)}`);
    lines.push(`    balance ${safeIdentifier(be.balance)}`);
    if (be.mode === 'http') {
      lines.push('    option httpchk GET /');
    }
    for (const srv of be.servers) {
      const safeSrvName = safeIdentifier(srv.name);
      const safeAddr = srv.address.replace(/[\r\n\s]+/g, '');
      let srvLine = `    server ${safeSrvName} ${safeAddr}:${srv.port}`;
      if (srv.check) {
        srvLine += ' check';
      }
      lines.push(srvLine);
    }
    lines.push('');
  }

  return lines.join('\n');
}
