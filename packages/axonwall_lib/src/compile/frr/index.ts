import type { FrrConfig, Interface } from '../../schemas/index.js';

export interface CompiledFrr {
  frrConf: string;
  daemons: Record<string, boolean>;
  daemonsConf: string;
}

/**
 * Compiles FrrConfig into modern FRRouting frr.conf and daemons configuration.
 * Supports BGP, OSPFv2, and BFD.
 */
export function compileFrr(config?: FrrConfig, interfaces: Interface[] = []): CompiledFrr {
  const daemons = {
    zebra: true,
    bgpd: false,
    ospfd: false,
    ospf6d: false,
    bfdd: false,
  };

  if (!config || !config.enabled) {
    return {
      frrConf: '# FRRouting is disabled\n',
      daemons,
      daemonsConf: generateDaemonsConf(daemons),
    };
  }

  const lines: string[] = [
    'frr version 10.0',
    'frr defaults traditional',
    'hostname axonwall',
    'log syslog informational',
    'service integrated-vtysh-config',
    '!',
  ];

  // BGP Section
  if (config.bgp && config.bgp.enabled) {
    daemons.bgpd = true;
    lines.push(`router bgp ${config.bgp.asNumber}`);
    lines.push(` bgp router-id ${config.bgp.routerId.replace(/[\r\n\s]+/g, '')}`);
    lines.push(' no bgp ebgp-requires-policy');

    const v4Nets: string[] = [];
    const v6Nets: string[] = [];
    for (const net of config.bgp.networks) {
      const cleanNet = net.replace(/[\r\n\s]+/g, '');
      if (!cleanNet) continue;
      if (cleanNet.includes(':')) v6Nets.push(cleanNet);
      else v4Nets.push(cleanNet);
    }
    for (const net of v4Nets) {
      lines.push(` network ${net}`);
    }

    const v6Neighbors: typeof config.bgp.neighbors = [];
    for (const neighbor of config.bgp.neighbors) {
      const safePeerIp = neighbor.peerIp.replace(/[\r\n\s]+/g, '');
      const isV6 = safePeerIp.includes(':');
      lines.push(` neighbor ${safePeerIp} remote-as ${neighbor.remoteAs}`);
      if (neighbor.description) {
        const safeDesc = neighbor.description.replace(/[\r\n]+/g, ' ').replace(/"/g, "'").trim();
        lines.push(` neighbor ${safePeerIp} description ${safeDesc}`);
      }
      if (neighbor.password) {
        const safePass = neighbor.password.replace(/[\r\n\s]+/g, '');
        lines.push(` neighbor ${safePeerIp} password ${safePass}`);
      }
      if (neighbor.bfd) {
        daemons.bfdd = true;
        lines.push(` neighbor ${safePeerIp} bfd`);
      }
      if (!isV6) {
        if (neighbor.nextHopSelf) {
          lines.push(` neighbor ${safePeerIp} next-hop-self`);
        }
        if (neighbor.softReconfiguration) {
          lines.push(` neighbor ${safePeerIp} soft-reconfiguration inbound`);
        }
      } else {
        lines.push(` no neighbor ${safePeerIp} activate`);
        v6Neighbors.push(neighbor);
      }
    }

    if (v6Nets.length > 0 || v6Neighbors.length > 0) {
      lines.push(' !');
      lines.push(' address-family ipv6 unicast');
      for (const net of v6Nets) {
        lines.push(`  network ${net}`);
      }
      for (const neighbor of v6Neighbors) {
        const safePeerIp = neighbor.peerIp.replace(/[\r\n\s]+/g, '');
        lines.push(`  neighbor ${safePeerIp} activate`);
        if (neighbor.nextHopSelf) {
          lines.push(`  neighbor ${safePeerIp} next-hop-self`);
        }
        if (neighbor.softReconfiguration) {
          lines.push(`  neighbor ${safePeerIp} soft-reconfiguration inbound`);
        }
      }
      lines.push(' exit-address-family');
    }
    lines.push('!');
  }

  // OSPF Section
  if (config.ospf && config.ospf.enabled) {
    daemons.ospfd = true;

    // Interface-level OSPF configurations
    const ifDeviceMap = new Map<string, string>();
    for (const iface of interfaces) {
      if (iface.name && iface.device) {
        ifDeviceMap.set(iface.name, iface.device);
      }
    }
    for (const area of config.ospf.areas) {
      const safeAreaId = area.areaId.replace(/[^a-zA-Z0-9.:_-]/g, '');
      for (const iface of area.interfaces) {
        const resolvedIf = ifDeviceMap.get(iface) || iface;
        const safeIf = resolvedIf.replace(/[^a-zA-Z0-9_.:-]/g, '');
        if (!safeIf) continue;
        lines.push(`interface ${safeIf}`);
        lines.push(` ip ospf area ${safeAreaId}`);
        lines.push('!');
      }
    }

    lines.push('router ospf');
    lines.push(` ospf router-id ${config.ospf.routerId.replace(/[\r\n\s]+/g, '')}`);

    if (config.ospf.redistributeConnected) {
      lines.push(' redistribute connected');
    }
    if (config.ospf.redistributeDefault) {
      lines.push(' default-information originate');
    }

    for (const area of config.ospf.areas) {
      const safeAreaId = area.areaId.replace(/[^a-zA-Z0-9.:_-]/g, '');
      for (const net of area.networks ?? []) {
        lines.push(` network ${net.replace(/[\r\n\s]+/g, '')} area ${safeAreaId}`);
      }
    }
    lines.push('!');
  }

  lines.push('line vty', '!');

  return {
    frrConf: lines.join('\n') + '\n',
    daemons,
    daemonsConf: generateDaemonsConf(daemons),
  };
}

function generateDaemonsConf(daemons: Record<string, boolean>): string {
  return [
    '# FRR daemons configuration',
    `zebra=${daemons.zebra ? 'yes' : 'no'}`,
    `bgpd=${daemons.bgpd ? 'yes' : 'no'}`,
    `ospfd=${daemons.ospfd ? 'yes' : 'no'}`,
    `ospf6d=${daemons.ospf6d ? 'yes' : 'no'}`,
    `bfdd=${daemons.bfdd ? 'yes' : 'no'}`,
    'fabricd=no',
    'vrrpd=no',
    'staticd=yes',
    'vtysh_enable=yes',
    'zebra_options="  -A 127.0.0.1 -s 90000000"',
    '',
  ].join('\n');
}
