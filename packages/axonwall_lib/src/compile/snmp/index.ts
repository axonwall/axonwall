import type { SnmpPluginConfig } from '../../schemas/index.js';

/**
 * Compiles Net-SNMP snmpd configuration (/etc/snmp/snmpd.conf).
 */
export function compileSnmpd(config: SnmpPluginConfig): string {
  const lines: string[] = [];
  const safeCommunity = config.community.split(/[\r\n]/)[0].trim().replace(/[\r\n\s]+/g, '');
  const safeLocation = config.sysLocation.split(/[\r\n]/)[0].trim();
  const safeContact = config.sysContact.split(/[\r\n]/)[0].trim();
  const port = Math.max(1, Math.min(65535, Number(config.listenPort) || 161));

  lines.push('# /etc/snmp/snmpd.conf - Managed by Axonwall SNMP Plugin');
  lines.push(`agentAddress udp:${port},udp6:[::1]:${port}`);
  lines.push('');
  lines.push(`rocommunity ${safeCommunity} default`);
  lines.push(`sysLocation ${safeLocation}`);
  lines.push(`sysContact ${safeContact}`);
  lines.push('');
  lines.push('# Include network interface stats and host resources');
  lines.push('view   systemonly  included   .1.3.6.1.2.1.1');
  lines.push('view   systemonly  included   .1.3.6.1.2.1.25.1');
  lines.push('view   all         included   .1');
  lines.push(`rocommunity ${safeCommunity} default -V all`);
  lines.push('');

  return lines.join('\n');
}
