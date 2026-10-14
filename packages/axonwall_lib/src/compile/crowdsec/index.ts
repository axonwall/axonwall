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

  const setName = config.remediationSetName || 'set_crowdsec_blacklists';
  const verdict = config.action === 'reject' ? 'reject' : 'drop';

  const bouncerYaml = `# Axonwall CrowdSec Firewall Bouncer Configuration
mode: nftables
log_mode: file
log_dir: /var/log/
log_level: info
log_compression: true
log_max_size: 100
log_max_backups: 3
log_max_age: 30

api_url: ${config.lapiUrl || 'http://127.0.0.1:8080/'}
api_key: ${config.apiKey || 'CROWDSEC_API_KEY_HERE'}
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
}`;

  const nftRule = config.logBanned
    ? `ip saddr @${setName} log prefix "axonwall-crowdsec-${verdict}: " ${verdict}`
    : `ip saddr @${setName} ${verdict}`;

  return {
    bouncerYaml,
    nftSetDefinition,
    nftRule,
  };
}
