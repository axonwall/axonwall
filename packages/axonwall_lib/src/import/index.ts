import type { FirewallVendor, ImportReport } from './types.js';
import { importPfsenseConfig } from './pfsense/index.js';
import { importOpnsenseConfig } from './opnsense/index.js';
import { importVyosConfig } from './vyos/index.js';
import { importMikrotikConfig } from './mikrotik/index.js';
import { importIptablesConfig } from './iptables/index.js';
import { importCiscoAsaConfig } from './cisco/index.js';

export * from './types.js';
export * from './pfsense/index.js';
export * from './opnsense/index.js';
export * from './vyos/index.js';
export * from './mikrotik/index.js';
export * from './iptables/index.js';
export * from './cisco/index.js';
export * from './analyzer.js';
export * from './merge.js';

export function detectFirewallType(content: string): FirewallVendor {
  const trimmed = content.trim();

  // 1. pfSense XML
  if (trimmed.includes('<pfsense>') || trimmed.includes('<pfsense ') || trimmed.includes('</pfsense>')) {
    return 'pfsense';
  }

  // 2. OPNsense XML
  if (trimmed.includes('<opnsense>') || trimmed.includes('<opnsense ') || trimmed.includes('</opnsense>')) {
    return 'opnsense';
  }

  // 3. Cisco ASA / FTD
  if (
    trimmed.includes('access-list') ||
    trimmed.includes('nameif ') ||
    trimmed.includes('security-level ') ||
    trimmed.includes('object-group network')
  ) {
    return 'cisco';
  }

  // 4. MikroTik RouterOS (.rsc)
  if (
    trimmed.includes('/ip firewall') ||
    trimmed.includes('/interface ethernet') ||
    trimmed.includes('RouterOS') ||
    (trimmed.includes('/ip address') && trimmed.includes('add '))
  ) {
    return 'mikrotik';
  }

  // 5. Linux iptables / nftables
  if (
    trimmed.includes('*filter') ||
    trimmed.includes('*nat') ||
    trimmed.includes('-A INPUT') ||
    trimmed.includes('-A FORWARD') ||
    trimmed.includes('table inet') ||
    trimmed.includes('table ip')
  ) {
    return 'iptables';
  }

  // 6. VyOS / EdgeOS
  if (
    trimmed.includes('interfaces {') ||
    trimmed.includes('firewall {') ||
    trimmed.includes('service {') ||
    trimmed.includes('protocols {') ||
    trimmed.toLowerCase().includes('vyos')
  ) {
    return 'vyos';
  }

  // Fallback heuristic: XML?
  if (trimmed.startsWith('<?xml') || trimmed.includes('<filter>')) {
    if (trimmed.includes('opnsense')) return 'opnsense';
    return 'pfsense';
  }

  return 'pfsense';
}

export function importFirewallConfig(content: string, forcedVendor?: FirewallVendor): ImportReport {
  const vendor = forcedVendor || detectFirewallType(content);

  switch (vendor) {
    case 'pfsense':
      return importPfsenseConfig(content);
    case 'opnsense':
      return importOpnsenseConfig(content);
    case 'vyos':
      return importVyosConfig(content);
    case 'mikrotik':
      return importMikrotikConfig(content);
    case 'iptables':
      return importIptablesConfig(content);
    case 'cisco':
      return importCiscoAsaConfig(content);
    default:
      throw new Error(`Unsupported firewall vendor: ${vendor}`);
  }
}
