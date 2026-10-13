import type { DesiredState } from '../schemas/index.js';

export type FirewallVendor = 'pfsense' | 'opnsense' | 'vyos' | 'mikrotik' | 'iptables' | 'cisco';

export interface ImportReport {
  success: boolean;
  vendor: FirewallVendor;
  version?: string;
  sourceFormat?: string;
  interfacesCount: number;
  vlansCount: number;
  aliasesCount: number;
  rulesCount: number;
  natRulesCount: number;
  dhcpSubnetsCount: number;
  dnsOverridesCount: number;
  routesCount: number;
  warnings: string[];
  state: DesiredState;
}
