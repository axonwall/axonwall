import type { OpenVpnConfig, OpenVpnServer } from '../../schemas/index.js';

export interface CompiledOpenVpnServer {
  name: string;
  serverConf: string;
  ccdFiles: Record<string, string>; // filename -> content
}

export interface CompiledOpenVpn {
  servers: CompiledOpenVpnServer[];
}

/**
 * Compiles OpenVpnConfig into OpenVPN 2.6 configuration files with Linux Kernel Data Channel Offload (DCO).
 * Also outputs Client-Specific Override (CSO) configuration files.
 */
export function compileOpenVpn(config?: OpenVpnConfig): CompiledOpenVpn {
  if (!config || !config.enabled || !config.servers || config.servers.length === 0) {
    return { servers: [] };
  }

  const servers: CompiledOpenVpnServer[] = [];

  for (const server of config.servers) {
    if (!server.enabled) continue;
    servers.push(compileSingleServer(server));
  }

  return { servers };
}

function compileSingleServer(server: OpenVpnServer): CompiledOpenVpnServer {
  const safeName = server.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const safeCommentName = server.name.replace(/[\r\n]+/g, ' ').trim();
  const safeDevName = (server.devName || 'ovpn-dco0').replace(/[^a-zA-Z0-9_-]/g, '');
  const [networkIp, cidrStr] = server.tunnelNetwork.split('/');
  const prefix = Number.parseInt(cidrStr || '24', 10);
  const netmask = cidrToNetmask(prefix);

  const lines: string[] = [
    `# Axonwall OpenVPN 2.6 Server: ${safeCommentName}`,
    `# Mode: ${server.dcoEnabled ? 'Linux Kernel DCO (Data Channel Offload)' : 'Standard tun/tap'}`,
    `proto ${server.protocol === 'tcp' ? 'tcp-server' : 'udp'}`,
    `port ${server.port}`,
    `dev ${safeDevName}`,
    `dev-type ${server.deviceType || 'tun'}`,
    'topology subnet',
    `server ${networkIp} ${netmask}`,
    `data-ciphers ${server.cipher || 'AES-256-GCM'}:CHACHA20-POLY1305`,
    `auth ${server.authDigest || 'SHA256'}`,
    'keepalive 10 120',
    'persist-key',
    'persist-tun',
    `client-config-dir /var/lib/axonwall/openvpn/${safeName}/ccd`,
  ];

  if (server.dcoEnabled) {
    lines.push('# Kernel DCO optimization enabled');
  }

  if (server.clientToClient) {
    lines.push('client-to-client');
  }

  if (server.duplicateCn) {
    lines.push('duplicate-cn');
  }

  if (server.localNetwork) {
    const [localIp, localCidr] = server.localNetwork.split('/');
    const localMask = cidrToNetmask(Number.parseInt(localCidr || '24', 10));
    lines.push(`push "route ${localIp} ${localMask}"`);
  }

  if (server.caCert) {
    lines.push(`ca /var/lib/axonwall/openvpn/${safeName}/ca.crt`);
  }
  if (server.serverCert) {
    lines.push(`cert /var/lib/axonwall/openvpn/${safeName}/server.crt`);
  }
  if (server.serverKey) {
    lines.push(`key /var/lib/axonwall/openvpn/${safeName}/server.key`);
  }
  if (server.dhParams) {
    lines.push(`dh /var/lib/axonwall/openvpn/${safeName}/dh.pem`);
  }

  lines.push('verb 3');
  lines.push('status /var/log/axonwall/openvpn-status.log 10');

  // Client-Specific Overrides (CSO)
  const ccdFiles: Record<string, string> = {};
  if (server.cso && server.cso.length > 0) {
    for (const cso of server.cso) {
      const safeCn = cso.commonName.replace(/[^a-zA-Z0-9_.-]/g, '_');
      if (!safeCn || safeCn.includes('..') || safeCn.startsWith('.')) {
        continue;
      }
      const csoLines: string[] = [`# Client Specific Override for ${safeCn}`];
      if (cso.assignedIp) {
        csoLines.push(`ifconfig-push ${cso.assignedIp} ${netmask}`);
      }
      for (const route of cso.pushRoutes) {
        const [rIp, rCidr] = route.split('/');
        const rMask = cidrToNetmask(Number.parseInt(rCidr || '24', 10));
        csoLines.push(`push "route ${rIp} ${rMask}"`);
      }
      ccdFiles[safeCn] = csoLines.join('\n') + '\n';
    }
  }

  return {
    name: safeName,
    serverConf: lines.join('\n') + '\n',
    ccdFiles,
  };
}

/**
 * Generates client .ovpn configuration file for road warrior export.
 */
export function generateClientOvpnProfile(params: {
  serverHost: string;
  serverPort: number;
  protocol?: 'udp' | 'tcp';
  cipher?: string;
  caCert?: string;
  clientCert?: string;
  clientKey?: string;
}): string {
  const proto = params.protocol || 'udp';
  const cipher = params.cipher || 'AES-256-GCM';

  const lines: string[] = [
    'client',
    `dev tun`,
    `proto ${proto}`,
    `remote ${params.serverHost} ${params.serverPort}`,
    'resolv-retry infinite',
    'nobind',
    'persist-key',
    'persist-tun',
    'remote-cert-tls server',
    `data-ciphers ${cipher}:CHACHA20-POLY1305`,
    'verb 3',
  ];

  if (params.caCert) {
    lines.push('<ca>', params.caCert.trim(), '</ca>');
  }
  if (params.clientCert) {
    lines.push('<cert>', params.clientCert.trim(), '</cert>');
  }
  if (params.clientKey) {
    lines.push('<key>', params.clientKey.trim(), '</key>');
  }

  return lines.join('\n') + '\n';
}

function cidrToNetmask(prefix: number): string {
  const mask = [];
  for (let i = 0; i < 4; i++) {
    const n = Math.min(prefix, 8);
    mask.push(256 - Math.pow(2, 8 - n));
    prefix -= n;
  }
  return mask.join('.');
}
