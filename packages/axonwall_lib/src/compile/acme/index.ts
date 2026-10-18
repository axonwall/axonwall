import type { AcmeConfig, AcmeCertificate } from '../../schemas/index.js';

export interface CompiledAcme {
  renewScript: string;
  hookScripts: Record<string, string>; // service -> reload command
  deployHooks: { path: string; content: string }[];
}

const DOMAIN_REGEX = /^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

/**
 * Compiles AcmeConfig into automated certificate issuance and post-renewal deployment scripts.
 * Supports HTTP-01 and DNS-01 challenges, and automatic service reload hooks.
 */
export function compileAcme(config?: AcmeConfig): CompiledAcme {
  if (!config || !config.enabled || !config.certificates || config.certificates.length === 0) {
    return {
      renewScript: '#!/bin/bash\n# ACME automated certificates disabled\nexit 0\n',
      hookScripts: {},
      deployHooks: [],
    };
  }

  const lines: string[] = [
    '#!/bin/bash',
    '# Axonwall Automated ACME Certificate Renewal Script',
    'set -e',
    '',
    'mkdir -p /var/www/acme-challenge/.well-known/acme-challenge',
    'mkdir -p /var/lib/axonwall/certs',
    '',
  ];

  const hookScripts: Record<string, string> = {
    webgui: 'systemctl reload-or-restart axonwall || true',
    openvpn: 'systemctl reload-or-restart openvpn@* || true',
    ipsec: 'swanctl --load-creds && swanctl --load-conns || true',
    haproxy: 'systemctl reload haproxy || true',
  };

  const deployHooks: { path: string; content: string }[] = [];

  for (const cert of config.certificates) {
    const safeName = cert.name.replace(/[^a-zA-Z0-9_-]/g, '_');
    const safeDns = (cert.dnsProvider || 'cloudflare').replace(/[^a-zA-Z0-9_-]/g, '_');

    if (!DOMAIN_REGEX.test(cert.domain)) {
      throw new Error(`Invalid domain name in certificate config: ${cert.domain}`);
    }

    const domainArgs = [cert.domain];
    for (const alt of cert.altNames || []) {
      if (!DOMAIN_REGEX.test(alt)) {
        throw new Error(`Invalid altName in certificate config: ${alt}`);
      }
      domainArgs.push(alt);
    }

    lines.push(`### Certificate: ${cert.domain} ###`);
    const allDomains = domainArgs.map((d) => `-d ${d}`).join(' ');

    if (cert.challengeType === 'http-01') {
      lines.push(
        `# HTTP-01 Webroot challenge`,
        `certbot certonly --webroot -w /var/www/acme-challenge \\`,
        `  ${allDomains} \\`,
        `  --non-interactive --agree-tos \\`,
        `  --deploy-hook "/var/lib/axonwall/certs/deploy-${safeName}.sh" || true`
      );
    } else {
      lines.push(
        `# DNS-01 API challenge via ${safeDns}`,
        `certbot certonly --dns-${safeDns} \\`,
        `  ${allDomains} \\`,
        `  --non-interactive --agree-tos \\`,
        `  --deploy-hook "/var/lib/axonwall/certs/deploy-${safeName}.sh" || true`
      );
    }

    // Deploy hook commands for this certificate
    const reloadCommands = (cert.deployServices || []).map((svc) => hookScripts[svc] || `# unknown svc: ${svc}`);
    deployHooks.push({
      path: `/var/lib/axonwall/certs/deploy-${safeName}.sh`,
      content: [
        '#!/bin/bash',
        `# Auto-generated deploy hook for ${safeName}`,
        'set -e',
        ...reloadCommands,
        '',
      ].join('\n'),
    });
    lines.push('');
  }

  return {
    renewScript: lines.join('\n') + '\n',
    hookScripts,
    deployHooks,
  };
}
