import type { HaProxyPluginConfig } from '../../schemas/index.js';

/**
 * Compiles HAProxy configuration (/etc/haproxy/haproxy.cfg).
 */
export function compileHaProxy(config: HaProxyPluginConfig): string {
  const lines: string[] = [];

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
  lines.push(`    mode ${config.mode}`);
  lines.push('    option httplog');
  lines.push('    option dontlognull');
  lines.push('    timeout connect 5000ms');
  lines.push('    timeout client  50000ms');
  lines.push('    timeout server  50000ms');
  lines.push('');

  for (const fe of config.frontends) {
    lines.push(`frontend ${fe.name}`);
    let bindLine = `    bind *:${fe.bindPort}`;
    if (fe.ssl && fe.certName) {
      bindLine += ` ssl crt /etc/axonwall/certs/${fe.certName}.pem`;
    }
    lines.push(bindLine);
    lines.push(`    mode ${config.mode}`);
    if (config.mode === 'http') {
      lines.push('    option forwardfor');
      lines.push('    http-request set-header X-Forwarded-Proto https if { ssl_fc }');
    }
    lines.push(`    default_backend ${fe.defaultBackend}`);
    lines.push('');
  }

  for (const be of config.backends) {
    lines.push(`backend ${be.name}`);
    lines.push(`    mode ${be.mode}`);
    lines.push(`    balance ${be.balance}`);
    if (be.mode === 'http') {
      lines.push('    option httpchk GET /');
    }
    for (const srv of be.servers) {
      let srvLine = `    server ${srv.name} ${srv.address}:${srv.port}`;
      if (srv.check) {
        srvLine += ' check';
      }
      lines.push(srvLine);
    }
    lines.push('');
  }

  return lines.join('\n');
}
