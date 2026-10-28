import type { DesiredState } from '../schemas/index.js';

export type FirewallVendor = 'pfsense' | 'opnsense' | 'vyos' | 'mikrotik' | 'iptables' | 'cisco' | 'firewalld';

export interface ImportReviewItem {
  ruleId: string;
  ruleIndex: number;
  reason: 'negated_source' | 'negated_destination' | 'negated_both' | 'manual_review';
  originalMatchSummary: string;
  explanation: string;
  suggestedResolution: string;
}

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
  reviewItems?: ImportReviewItem[];
  state: DesiredState;
}
