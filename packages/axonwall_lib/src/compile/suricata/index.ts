import type { SuricataConfig } from '../../schemas/index.js';

export interface CompiledSuricata {
  suricataYaml: string;
  nftRules: string[];
}

export interface SuricataAlert {
  timestamp: string;
  gid: number;
  sid: number;
  rev: number;
  signature: string;
  category: string;
  severity: number; // 1 = High, 2 = Medium, 3 = Low
  srcIp: string;
  srcPort?: number;
  dstIp: string;
  dstPort?: number;
  proto: string;
  action: 'allowed' | 'blocked';
}

/**
 * Compiles SuricataConfig into suricata.yaml and nftables NFQUEUE diversion rules.
 * Supports NFQUEUE mode with fail-open and bypass semantics to prevent network outages if Suricata crashes.
 */
export function compileSuricata(config?: SuricataConfig): CompiledSuricata {
  if (!config || !config.enabled) {
    return {
      suricataYaml: '# Suricata IDS/IPS is disabled\n',
      nftRules: [],
    };
  }

  const homeNetList = config.homeNet.join(',');
  const isIps = config.mode === 'ips';

  const suricataYaml = `# Axonwall Suricata 7.0 Configuration (Auto-Generated)
%YAML 1.1
---
suricata-version: "7.0"

vars:
  address-groups:
    HOME_NET: "[${homeNetList}]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,8080,8000,8888"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"

default-log-dir: /var/log/suricata/

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer: yes
            http-body: yes
            metadata: yes
        - flow
        - dns:
            version: 2
        - http:
            extended: yes
        - tls:
            extended: yes

nfq:
  mode: ${isIps ? 'accept' : 'repeat'}
  repeat-mark: 1
  repeat-mask: 1
  bypass: ${config.nfqueueBypass ? 'yes' : 'no'}
  fail-open: ${config.nfqueueFailOpen ? 'yes' : 'no'}

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes

default-rule-path: /var/lib/axonwall/suricata/rules
rule-files:
  - suricata.rules
  - local.rules
`;

  // nftables NFQUEUE rules
  const nftRules: string[] = [];
  for (const iface of config.interfaces) {
    const queueAction = config.nfqueueBypass ? 'queue num 0-3 bypass' : 'queue num 0-3';
    nftRules.push(
      `iifname "${iface}" ${queueAction} comment "suricata-ips-inbound"`,
      `oifname "${iface}" ${queueAction} comment "suricata-ips-outbound"`
    );
  }

  return {
    suricataYaml,
    nftRules,
  };
}

/**
 * Parses a single line from Suricata's eve.json log into a typed alert.
 */
export function parseEveAlert(line: string): SuricataAlert | null {
  try {
    const data = JSON.parse(line);
    if (data.event_type !== 'alert' || !data.alert) {
      return null;
    }

    const action = data.alert.action === 'blocked' || data.alert.action === 'drop' ? 'blocked' : 'allowed';

    return {
      timestamp: data.timestamp || new Date().toISOString(),
      gid: data.alert.gid || 1,
      sid: data.alert.signature_id || 0,
      rev: data.alert.rev || 1,
      signature: data.alert.signature || 'Unknown signature',
      category: data.alert.category || 'Potentially Bad Traffic',
      severity: data.alert.severity || 3,
      srcIp: data.src_ip || '0.0.0.0',
      srcPort: data.src_port,
      dstIp: data.dest_ip || '0.0.0.0',
      dstPort: data.dest_port,
      proto: data.proto || 'TCP',
      action,
    };
  } catch {
    return null;
  }
}
