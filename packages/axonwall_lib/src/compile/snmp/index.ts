import type { SnmpPluginConfig } from '../../schemas/index.js';
import { isValidIPv4, isValidIPv6 } from '../../util/index.js';

function sanitizeSnmpToken(raw: string): string {
  return raw.split(/[\r\n]/)[0].trim().replace(/[\r\n"]/g, '');
}

/**
 * Compiles Net-SNMP snmpd configuration (/etc/snmp/snmpd.conf).
 * Supports SNMPv2c and SNMPv3 (USM authPriv / authNoPriv) as well as interface bind addresses.
 */
export function compileSnmpd(config: SnmpPluginConfig): string {
  const lines: string[] = [];
  const safeCommunity = config.community.split(/[\r\n]/)[0].trim().replace(/[\r\n\s]+/g, '');
  const safeLocation = config.sysLocation.split(/[\r\n]/)[0].trim();
  const safeContact = config.sysContact.split(/[\r\n]/)[0].trim();
  const port = Math.max(1, Math.min(65535, Number(config.listenPort) || 161));
  const version = config.version === 'v3' ? 'v3' : 'v2c';

  const validBindAddrs = (config.bindAddresses ?? [])
    .map((a) => a.trim())
    .filter((a) => isValidIPv4(a) || isValidIPv6(a));

  const agentAddrSpec =
    validBindAddrs.length > 0
      ? validBindAddrs.map((ip) => (ip.includes(':') ? `udp6:[${ip}]:${port}` : `udp:${ip}:${port}`)).join(',')
      : `udp:${port},udp6:[::1]:${port}`;

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
    for (const u of config.v3Users ?? []) {
      const user = sanitizeSnmpToken(u.username).replace(/\s+/g, '');
      const authPass = sanitizeSnmpToken(u.authPassword);
      const privPass = sanitizeSnmpToken(u.privPassword);
      if (!user || authPass.length < 8) continue;
      if (u.securityLevel === 'authNoPriv') {
        lines.push(`createUser ${user} ${u.authProtocol} "${authPass}"`);
        lines.push(`rouser ${user} auth -V all`);
      } else {
        if (privPass.length < 8) continue;
        lines.push(`createUser ${user} ${u.authProtocol} "${authPass}" ${u.privProtocol} "${privPass}"`);
        lines.push(`rouser ${user} priv -V all`);
      }
    }
  } else {
    lines.push(`rocommunity ${safeCommunity} default -V all`);
  }
  lines.push('');

  return lines.join('\n');
}
