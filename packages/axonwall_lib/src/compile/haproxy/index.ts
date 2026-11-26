import type { HaProxyPluginConfig } from '../../schemas/index.js';

/**
 * Compiles HAProxy configuration (/etc/haproxy/haproxy.cfg).
 */
function safeIdentifier(str: string): string {
  return str.replace(/[^a-zA-Z0-9_-]/g, '_');
}

export function sanitizeHaProxyHostname(raw?: string): string {
  if (!raw) return '';
  let trimmed = raw.trim().replace(/[\r\n\x00]/g, '');
  trimmed = trimmed.replace(/^https?:\/\//i, '');
  const slashIdx = trimmed.indexOf('/');
  if (slashIdx >= 0) trimmed = trimmed.slice(0, slashIdx);
  const colonIdx = trimmed.indexOf(':');
  if (colonIdx >= 0) trimmed = trimmed.slice(0, colonIdx);
  return trimmed.replace(/[^a-zA-Z0-9.-]/g, '').toLowerCase();
}

function safeHaProxyPath(raw: string): string {
  const clean = raw.trim().replace(/[\r\n\x00\s"';]/g, '');
  if (!clean.startsWith('/') || clean.includes('..')) return '';
  return clean;
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
      const safeStrictHost = sanitizeHaProxyHostname(fe.strictHost);
      if (safeStrictHost) {
        if (fe.ssl) {
          lines.push(`    acl valid_sni ssl_fc_sni -i ${safeStrictHost}`);
          lines.push(`    acl valid_host req.hdr(host),field(1,:) -i ${safeStrictHost}`);
          lines.push('    http-request silent-drop unless valid_sni valid_host');
        } else {
          lines.push(`    acl valid_host req.hdr(host),field(1,:) -i ${safeStrictHost}`);
          lines.push('    http-request silent-drop unless valid_host');
        }
      }

      const pathRules = fe.pathRules ?? [];
      if (pathRules.length > 0) {
        lines.push('    acl bad_traversal path_sub ..');
        lines.push('    acl bad_encoded_dot path_sub -i %2e');
        lines.push('    acl bad_encoded_slash path_sub -i %2f');
        lines.push('    http-request silent-drop if bad_traversal or bad_encoded_dot or bad_encoded_slash');
      }

      if (fe.sanitizeProxyHeaders) {
        lines.push('    http-request del-header X-Forwarded-For');
        lines.push('    http-request del-header X-Real-IP');
        lines.push('    http-request del-header X-Forwarded-Host');
        lines.push('    http-request del-header X-Forwarded-Proto');
        lines.push('    option forwardfor');
        lines.push('    http-request set-header X-Real-IP %[src]');
        lines.push(`    http-request set-header X-Forwarded-Proto ${fe.ssl ? 'https' : 'http'}`);
      } else {
        lines.push('    option forwardfor');
        lines.push('    http-request set-header X-Forwarded-Proto https if { ssl_fc }');
      }

      const compiledPathRules: Array<{ cond: string; backend: string }> = [];
      pathRules.forEach((rule, idx) => {
        const cleanPath = safeHaProxyPath(rule.path);
        if (!cleanPath) return;
        const matcher = rule.matchType === 'exact' ? 'path' : 'path_beg';
        const pathAcl = `allow_path_${idx}`;
        lines.push(`    acl ${pathAcl} ${matcher} ${cleanPath}`);
        let cond = pathAcl;
        const validMethods = (rule.methods ?? []).filter((m) =>
          ['GET', 'POST', 'HEAD', 'OPTIONS'].includes(m),
        );
        if (validMethods.length > 0) {
          const methodAcl = `allow_method_${idx}`;
          lines.push(`    acl ${methodAcl} method ${validMethods.join(' ')}`);
          cond = `${pathAcl} ${methodAcl}`;
        }
        lines.push(`    http-request set-var(txn.path_allowed) int(1) if ${cond}`);
        compiledPathRules.push({ cond, backend: safeIdentifier(rule.backend) });
      });

      if (fe.silentDropUnmatched) {
        if (compiledPathRules.length > 0) {
          lines.push('    http-request silent-drop unless { var(txn.path_allowed) -m int eq 1 }');
        } else {
          lines.push('    http-request silent-drop');
        }
      }

      for (const hr of fe.hostRules ?? []) {
        const cleanHost = sanitizeHaProxyHostname(hr.hostname);
        if (!cleanHost) continue;
        const aclId = `host_${safeIdentifier(cleanHost)}`;
        lines.push(`    acl ${aclId} hdr_dom(host) -i ${cleanHost}`);
        lines.push(`    use_backend ${safeIdentifier(hr.backend)} if ${aclId}`);
      }

      for (const pr of compiledPathRules) {
        lines.push(`    use_backend ${pr.backend} if ${pr.cond}`);
      }
    }
    if (!fe.silentDropUnmatched) {
      lines.push(`    default_backend ${safeIdentifier(fe.defaultBackend)}`);
    }
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
