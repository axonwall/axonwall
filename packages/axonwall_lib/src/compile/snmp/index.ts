import type { SnmpPluginConfig } from '../../schemas/index.js';
import { isValidIPv4, isValidIPv6 } from '../../util/index.js';

function sanitizeSnmpToken(raw: string): string {
  return raw.split(/[\r\n]/)[0].trim().replace(/[\r\n"\\]/g, '');
}

function isWildcardAddress(addr: string): boolean {
  const lower = addr.toLowerCase();
  return lower === '0.0.0.0' || lower === '::' || lower === '::0' || lower === '0:0:0:0:0:0:0:0';
}

function getValidSnmpV3Users(config: SnmpPluginConfig) {
  return (config.v3Users ?? [])
    .map((u) => ({
      user: sanitizeSnmpToken(u.username).replace(/\s+/g, ''),
      authProtocol: u.authProtocol || 'SHA-256',
      authPass: sanitizeSnmpToken(u.authPassword),
      privProtocol: u.privProtocol || 'AES',
      privPass: sanitizeSnmpToken(u.privPassword),
      securityLevel: u.securityLevel === 'authNoPriv' ? 'authNoPriv' : 'authPriv',
    }))
    .filter((u) => u.user && u.authPass.length >= 8 && (u.securityLevel === 'authNoPriv' || u.privPass.length >= 8));
}

/**
 * Compiles Net-SNMP snmpd configuration (/etc/snmp/snmpd.conf).
 * Defaults to SNMPv3 authPriv bound to loopback/LAN only (never 0.0.0.0).
 * USM createUser credentials are written separately to 0o600 /var/lib/snmp/snmpd.conf.
 */
export function compileSnmpd(config: SnmpPluginConfig, defaultBindAddresses?: string[]): string {
  const lines: string[] = [];
  const safeCommunity = sanitizeSnmpToken(config.community || '').replace(/\s+/g, '');
  const safeLocation = config.sysLocation.split(/[\r\n]/)[0].trim();
  const safeContact = config.sysContact.split(/[\r\n]/)[0].trim();
  const port = Math.max(1, Math.min(65535, Number(config.listenPort) || 161));
  const version = config.version === 'v2c' ? 'v2c' : 'v3';

  const configuredBindAddrs = (config.bindAddresses ?? [])
    .map((a) => a.trim())
    .filter((a) => (isValidIPv4(a) || isValidIPv6(a)) && !isWildcardAddress(a));

  const fallbackBindAddrs = (defaultBindAddresses ?? [])
    .map((a) => a.trim())
    .filter((a) => (isValidIPv4(a) || isValidIPv6(a)) && !isWildcardAddress(a));

  const validBindAddrs = configuredBindAddrs.length > 0 ? configuredBindAddrs : fallbackBindAddrs;

  const agentAddrSpec =
    validBindAddrs.length > 0
      ? validBindAddrs.map((ip) => (ip.includes(':') ? `udp6:[${ip}]:${port}` : `udp:${ip}:${port}`)).join(',')
      : `udp:127.0.0.1:${port},udp6:[::1]:${port}`;

  lines.push('# /etc/snmp/snmpd.conf - Managed by Axonwall SNMP Plugin');
  lines.push(`agentAddress ${agentAddrSpec}`);
  lines.push('');
  lines.push(`sysLocation ${safeLocation}`);
  lines.push(`sysContact ${safeContact}`);
  lines.push('');
  lines.push('# Include network interface stats and host resources');
  lines.push('view   systemonly  included   .1.3.6.1.2.1.1');
  lines.push('view   systemonly  included   .1.3.6.1.2.1.25.1');
  lines.push('view   all         included   .1');

  if (version === 'v3') {
    for (const u of getValidSnmpV3Users(config)) {
      if (u.securityLevel === 'authNoPriv') {
        lines.push(`rouser ${u.user} auth -V all`);
      } else {
        lines.push(`rouser ${u.user} priv -V all`);
      }
    }
  } else if (safeCommunity) {
    lines.push(`rocommunity ${safeCommunity} default -V all`);
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Compiles Net-SNMP persistent USM user credentials (/var/lib/snmp/snmpd.conf, 0o600).
 * Returns empty string when SNMPv3 is inactive or has no valid users.
 */
export function compileSnmpdPersistentUsers(config: SnmpPluginConfig): string {
  const version = config.version === 'v2c' ? 'v2c' : 'v3';
  if (version !== 'v3') return '';

  const users = getValidSnmpV3Users(config);
  if (users.length === 0) return '';

  const lines: string[] = [
    '# /var/lib/snmp/snmpd.conf - Managed by Axonwall SNMP Plugin (0600)',
  ];
  for (const u of users) {
    if (u.securityLevel === 'authNoPriv') {
      lines.push(`createUser ${u.user} ${u.authProtocol} "${u.authPass}"`);
    } else {
      lines.push(`createUser ${u.user} ${u.authProtocol} "${u.authPass}" ${u.privProtocol} "${u.privPass}"`);
    }
  }
  lines.push('');
  return lines.join('\n');
}
