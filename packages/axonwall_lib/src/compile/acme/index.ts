import type { AcmeConfig, AcmeCertificate } from '../../schemas/index.js';

export interface CompiledAcme {
  renewScript: string;
  hookScripts: Record<string, string>; // service -> reload command
}

/**
 * Compiles AcmeConfig into automated certificate issuance and post-renewal deployment scripts.
 * Supports HTTP-01 and DNS-01 challenges, and automatic service reload hooks.
 */
export function compileAcme(config?: AcmeConfig): CompiledAcme {
  if (!config || !config.enabled || !config.certificates || config.certificates.length === 0) {
    return {
      renewScript: '#!/bin/bash\n# ACME automated certificates disabled\nexit 0\n',
      hookScripts: {},
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

  for (const cert of config.certificates) {
    lines.push(`### Certificate: ${cert.domain} ###`);
    const allDomains = [cert.domain, ...cert.altNames].map((d) => `-d ${d}`).join(' ');

    if (cert.challengeType === 'http-01') {
      lines.push(
        `# HTTP-01 Webroot challenge`,
        `certbot certonly --webroot -w /var/www/acme-challenge \\`,
        `  ${allDomains} \\`,
        `  --non-interactive --agree-tos \\`,
        `  --deploy-hook "/var/lib/axonwall/certs/deploy-${cert.name}.sh" || true`
      );
    } else {
      lines.push(
        `# DNS-01 API challenge via ${cert.dnsProvider || 'manual'}`,
        `certbot certonly --dns-${cert.dnsProvider || 'cloudflare'} \\`,
        `  ${allDomains} \\`,
        `  --non-interactive --agree-tos \\`,
        `  --deploy-hook "/var/lib/axonwall/certs/deploy-${cert.name}.sh" || true`
      );
    }

    // Deploy hook commands for this certificate
    const reloadCommands = cert.deployServices.map((svc) => hookScripts[svc] || '# unknown svc');
    lines.push('');
  }

  return {
    renewScript: lines.join('\n') + '\n',
    hookScripts,
  };
}
