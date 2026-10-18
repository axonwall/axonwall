import type { CrowdSecConfig } from '../../schemas/index.js';

export interface CompiledCrowdSec {
  bouncerYaml: string;
  nftSetDefinition: string;
  nftRule: string;
}

/**
 * Compiles CrowdSecConfig into crowdsec-firewall-bouncer.yaml and nftables bouncer rule.
 * Directly integrates with native nftables named sets in table inet axonwall.
 */
export function compileCrowdSec(config?: CrowdSecConfig): CompiledCrowdSec {
  if (!config || !config.enabled) {
    return {
      bouncerYaml: '# CrowdSec integration is disabled\n',
      nftSetDefinition: '',
      nftRule: '',
    };
  }

  const rawSetName = config.remediationSetName
    ?.split(/[\r\n\s;]/)[0]
    .replace(/[^a-zA-Z0-9_]/g, '');
  const setName = rawSetName || 'set_crowdsec_blacklists';
  const verdict = config.action === 'reject' ? 'reject' : 'drop';
  const lapiUrl = (config.lapiUrl || 'http://127.0.0.1:8080/').split(/[\r\n]/)[0].replace(/["']/g, '').trim();
  const apiKey = (config.apiKey || 'CROWDSEC_API_KEY_HERE').split(/[\r\n]/)[0].replace(/["']/g, '').trim();

  const bouncerYaml = `# Axonwall CrowdSec Firewall Bouncer Configuration
mode: nftables
log_mode: file
log_dir: /var/log/
log_level: info
log_compression: true
log_max_size: 100
log_max_backups: 3
log_max_age: 30

api_url: ${lapiUrl}
api_key: ${apiKey}
insecure_skip_verify: false

disable_ipv6: false

# Native nftables binding into table inet axonwall
nftables:
  ipv4:
    enabled: true
    set-only: true
    table: axonwall
    chain: input
    family: inet
    set: ${setName}
    rule: "ip saddr @${setName} ${verdict}"
  ipv6:
    enabled: true
    set-only: true
    table: axonwall
    chain: input
    family: inet
    set: ${setName}_v6
    rule: "ip6 saddr @${setName}_v6 ${verdict}"
`;

  const nftSetDefinition = `set ${setName} {
  type ipv4_addr
  flags interval, timeout
}
set ${setName}_v6 {
  type ipv6_addr
  flags interval, timeout
}`;

  const nftRule = config.logBanned
    ? `ip saddr @${setName} log prefix "axonwall-crowdsec-${verdict}: " ${verdict}\n    ip6 saddr @${setName}_v6 log prefix "axonwall-crowdsec-${verdict}: " ${verdict}`
    : `ip saddr @${setName} ${verdict}\n    ip6 saddr @${setName}_v6 ${verdict}`;

  return {
    bouncerYaml,
    nftSetDefinition,
    nftRule,
  };
}
