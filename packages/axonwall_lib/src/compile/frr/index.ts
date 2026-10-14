import type { FrrConfig } from '../../schemas/index.js';

export interface CompiledFrr {
  frrConf: string;
  daemons: Record<string, boolean>;
  daemonsConf: string;
}

/**
 * Compiles FrrConfig into modern FRRouting frr.conf and daemons configuration.
 * Supports BGP, OSPFv2, and BFD.
 */
export function compileFrr(config?: FrrConfig): CompiledFrr {
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
    lines.push(` bgp router-id ${config.bgp.routerId}`);
    lines.push(' no bgp ebgp-requires-policy');

    for (const net of config.bgp.networks) {
      lines.push(` network ${net}`);
    }

    for (const neighbor of config.bgp.neighbors) {
      lines.push(` neighbor ${neighbor.peerIp} remote-as ${neighbor.remoteAs}`);
      if (neighbor.description) {
        lines.push(` neighbor ${neighbor.peerIp} description ${neighbor.description}`);
      }
      if (neighbor.password) {
        lines.push(` neighbor ${neighbor.peerIp} password ${neighbor.password}`);
      }
      if (neighbor.bfd) {
        daemons.bfdd = true;
        lines.push(` neighbor ${neighbor.peerIp} bfd`);
      }
      if (neighbor.nextHopSelf) {
        lines.push(` neighbor ${neighbor.peerIp} next-hop-self`);
      }
      if (neighbor.softReconfiguration) {
        lines.push(` neighbor ${neighbor.peerIp} soft-reconfiguration inbound`);
      }
    }
    lines.push('!');
  }

  // OSPF Section
  if (config.ospf && config.ospf.enabled) {
    daemons.ospfd = true;

    // Interface-level OSPF configurations
    for (const area of config.ospf.areas) {
      for (const iface of area.interfaces) {
        lines.push(`interface ${iface}`);
        lines.push(` ip ospf area ${area.areaId}`);
        lines.push('!');
      }
    }

    lines.push('router ospf');
    lines.push(` ospf router-id ${config.ospf.routerId}`);

    if (config.ospf.redistributeConnected) {
      lines.push(' redistribute connected');
    }
    if (config.ospf.redistributeDefault) {
      lines.push(' default-information originate');
    }

    for (const area of config.ospf.areas) {
      for (const net of area.networks) {
        lines.push(` network ${net} area ${area.areaId}`);
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
