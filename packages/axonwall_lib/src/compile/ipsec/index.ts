import type { IpsecConfig, IpsecTunnel } from '../../schemas/index.js';

export interface CompiledIpsec {
  swanctlConf: string;
  xfrmSetupCommands: string[];
}

/**
 * Compiles an IpsecConfig into strongSwan swanctl.conf format and kernel XFRM interface commands.
 * Supports route-based (XFRM interface with if_id) and policy-based IKEv2 tunnels.
 */
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
    const localTs = tunnel.localTs.map((t) => t.replace(/[\r\n\s]+/g, '')).join(', ');
    const remoteTs = tunnel.remoteTs.map((t) => t.replace(/[\r\n\s]+/g, '')).join(', ');
    const ikeProps = tunnel.ikeProposals.map((p) => p.replace(/[\r\n\s]+/g, '')).join(', ');
    const espProps = tunnel.espProposals.map((p) => p.replace(/[\r\n\s]+/g, '')).join(', ');
    const safeDpdAction = (tunnel.dpdAction || 'restart').replace(/[\r\n\s]+/g, '');
    const safeAuth = (tunnel.authMethod || 'psk').replace(/[\r\n\s]+/g, '');
    const safeLocalAddr = (tunnel.localAddress || '%any').replace(/[\r\n\s]+/g, '');
    const safeRemoteAddr = tunnel.remoteAddress.replace(/[\r\n\s]+/g, '');

    let childAttrs = `        local_ts = ${localTs}
        remote_ts = ${remoteTs}
        esp_proposals = ${espProps}
        dpd_action = ${safeDpdAction}
        start_action = start`;

    if (tunnel.routeBased && tunnel.xfrmInterfaceId) {
      childAttrs += `\n        if_id_in = ${tunnel.xfrmInterfaceId}\n        if_id_out = ${tunnel.xfrmInterfaceId}`;

      // Shell command to create the XFRM interface if it doesn't exist
      const ifName = `xfrm${tunnel.xfrmInterfaceId}`;
      xfrmCommands.push(
        `ip link add ${ifName} type xfrm if_id ${tunnel.xfrmInterfaceId} 2>/dev/null || true`,
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
      const safePsk = tunnel.presharedKey.replace(/[\r\n]+/g, '').replace(/[\\"]/g, '\\$&');
      const secret = `  ike-${safeName} {
    secret = "${safePsk}"
  }`;
      secretBlocks.push(secret);
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
