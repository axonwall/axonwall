import type { IpsecConfig, IpsecTunnel } from '../../schemas/index.js';

export interface CompiledIpsec {
  swanctlConf: string;
  xfrmSetupCommands: string[];
}

/**
 * Compiles an IpsecConfig into strongSwan swanctl.conf format and kernel XFRM interface commands.
 * Supports route-based (XFRM interface with if_id) and policy-based IKEv2 tunnels.
 */
const SAFE_IPSEC_VALUE_REGEX = /^[a-zA-Z0-9._:@/%-]+$/;

function assertIpsecToken(v: string, label: string): string {
  const cleaned = String(v ?? '').trim();
  if (!cleaned || !SAFE_IPSEC_VALUE_REGEX.test(cleaned)) {
    throw new Error(`Invalid IPsec ${label}: ${v}`);
  }
  return cleaned;
}

export function compileIpsec(config?: IpsecConfig): CompiledIpsec {
  if (!config || !config.enabled || !config.tunnels || config.tunnels.length === 0) {
    return {
      swanctlConf: '# IPsec is disabled\nconnections {}\nsecrets {}\n',
      xfrmSetupCommands: [],
    };
  }

  const connectionBlocks: string[] = [];
  const secretBlocks: string[] = [];
  const xfrmCommands: string[] = [];

  for (const tunnel of config.tunnels) {
    if (!tunnel.enabled) continue;

    const safeName = tunnel.name.replace(/[^a-zA-Z0-9_-]/g, '_');
    const localTs = tunnel.localTs.map((t) => assertIpsecToken(t, 'localTs')).join(', ');
    const remoteTs = tunnel.remoteTs.map((t) => assertIpsecToken(t, 'remoteTs')).join(', ');
    const ikeProps = tunnel.ikeProposals.map((p) => assertIpsecToken(p, 'ikeProposal')).join(', ');
    const espProps = tunnel.espProposals.map((p) => assertIpsecToken(p, 'espProposal')).join(', ');
    const safeDpdAction = assertIpsecToken(tunnel.dpdAction || 'restart', 'dpdAction');
    const safeAuth = assertIpsecToken(tunnel.authMethod || 'psk', 'authMethod');
    const safeLocalAddr = assertIpsecToken(tunnel.localAddress || '%any', 'localAddress');
    const safeRemoteAddr = assertIpsecToken(tunnel.remoteAddress, 'remoteAddress');

    let childAttrs = `        local_ts = ${localTs}
        remote_ts = ${remoteTs}
        esp_proposals = ${espProps}
        dpd_action = ${safeDpdAction}
        start_action = start`;

    if (tunnel.routeBased && tunnel.xfrmInterfaceId) {
      const xfrmId = Math.trunc(tunnel.xfrmInterfaceId);
      childAttrs += `\n        if_id_in = ${xfrmId}\n        if_id_out = ${xfrmId}`;

      // Shell command to create the XFRM interface if it doesn't exist
      const ifName = `xfrm${xfrmId}`;
      xfrmCommands.push(
        `ip link add ${ifName} type xfrm if_id ${xfrmId} 2>/dev/null || true`,
        `ip link set dev ${ifName} up`
      );
    }

    const conn = `  ${safeName} {
    version = 2
    local_addrs = ${safeLocalAddr}
    remote_addrs = ${safeRemoteAddr}
    proposals = ${ikeProps}
    local {
      auth = ${safeAuth}
    }
    remote {
      auth = ${safeAuth}
    }
    children {
      ${safeName}-child {
${childAttrs}
      }
    }
  }`;

    connectionBlocks.push(conn);

    if (tunnel.presharedKey) {
      const safePsk = tunnel.presharedKey.replace(/[\r\n\0]+/g, '').replace(/[\\"]/g, '\\$&');
      const secretLines = [`  ike-${safeName} {`];
      if (safeLocalAddr !== '%any') {
        secretLines.push(`    id-local = ${safeLocalAddr}`);
      }
      if (safeRemoteAddr !== '%any') {
        secretLines.push(`    id-remote = ${safeRemoteAddr}`);
      }
      secretLines.push(`    secret = "${safePsk}"`, '  }');
      secretBlocks.push(secretLines.join('\n'));
    }
  }

  const swanctlConf = `# Axonwall strongSwan swanctl.conf (auto-generated)
connections {
${connectionBlocks.join('\n\n')}
}

secrets {
${secretBlocks.join('\n\n')}
}
`;

  return {
    swanctlConf,
    xfrmSetupCommands: xfrmCommands,
  };
}
