import type { SnmpPluginConfig } from '../../schemas/index.js';

/**
 * Compiles Net-SNMP snmpd configuration (/etc/snmp/snmpd.conf).
 */
export function compileSnmpd(config: SnmpPluginConfig): string {
  const lines: string[] = [];

  lines.push('# /etc/snmp/snmpd.conf - Managed by Axonwall SNMP Plugin');
  lines.push(`agentAddress udp:${config.listenPort},udp6:[::1]:${config.listenPort}`);
  lines.push('');
  lines.push(`rocommunity ${config.community} default`);
  lines.push(`sysLocation ${config.sysLocation}`);
  lines.push(`sysContact ${config.sysContact}`);
  lines.push('');
  lines.push('# Include network interface stats and host resources');
  lines.push('view   systemonly  included   .1.3.6.1.2.1.1');
  lines.push('view   systemonly  included   .1.3.6.1.2.1.25.1');
  lines.push('view   all         included   .1');
  lines.push(`rocommunity ${config.community} default -V all`);
  lines.push('');

  return lines.join('\n');
}
