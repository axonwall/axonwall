import type { HighAvailabilityConfig, DesiredState, HaSyncSections } from '../../schemas/index.js';

/**
 * Compiles keepalived VRRP configuration (/etc/keepalived/keepalived.conf).
 */
export function compileKeepalived(ha: HighAvailabilityConfig, hostname: string = 'axonwall'): string {
  const lines: string[] = [];

  lines.push('! Configuration File for keepalived (Axonwall Managed)');
  lines.push('');
  lines.push('global_defs {');
  lines.push(`    router_id ${hostname}`);
  lines.push('    script_user root');
  lines.push('    enable_script_security');
  lines.push('    vrrp_garp_master_refresh 60');
  lines.push('}');
  lines.push('');

  // Track script for local axonwalld daemon health
  lines.push('vrrp_script chk_axonwalld {');
  lines.push('    script "/usr/bin/pgrep -x axonwalld"');
  lines.push('    interval 2');
  lines.push('    weight 2');
  lines.push('}');
  lines.push('');

  for (const vrrp of ha.vrrpInstances) {
    const isMaster = ha.nodeRole === 'master' && !ha.maintenanceMode;
    // In maintenance mode, drop priority to lowest to force peer takeover
    const effectivePriority = ha.maintenanceMode ? 1 : vrrp.priority;

    lines.push(`vrrp_instance ${vrrp.name} {`);
    lines.push(`    state ${isMaster ? 'MASTER' : 'BACKUP'}`);
    lines.push(`    interface ${vrrp.interface}`);
    lines.push(`    virtual_router_id ${vrrp.vrid}`);
    lines.push(`    priority ${effectivePriority}`);
    lines.push('    advert_int 1');
    lines.push('    nopreempt');

    if (vrrp.authPassword) {
      lines.push('    authentication {');
      lines.push('        auth_type PASS');
      lines.push(`        auth_pass ${vrrp.authPassword.slice(0, 8)}`);
      lines.push('    }');
    }

    lines.push('    virtual_ipaddress {');
    for (const vip of vrrp.virtualIps) {
      lines.push(`        ${vip}`);
    }
    lines.push('    }');

    lines.push('    track_script {');
    lines.push('        chk_axonwalld');
    lines.push('    }');

    lines.push('    notify_master "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -c"');
    lines.push('    notify_backup "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -f"');
    lines.push('    notify_fault  "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -t"');
    lines.push('}');
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Compiles conntrackd configuration (/etc/conntrackd/conntrackd.conf) for state sync.
 */
export function compileConntrackd(ha: HighAvailabilityConfig, localIp: string = '127.0.0.1'): string {
  const sync = ha.conntrackSync;
  const lines: string[] = [];

  lines.push('# conntrackd.conf - Axonwall High Availability State Synchronization');
  lines.push('Sync {');
  lines.push('    Mode FTFW {');
  lines.push('        ResendQueueSize 131072');
  lines.push('        CommitTimeout 180');
  lines.push('        PurgeTimeout 60');
  lines.push('        ACKWindowSize 300');
  lines.push('    }');
  lines.push('');

  if (sync.protocol === 'multicast') {
    lines.push('    Multicast {');
    lines.push(`        IPv4_address 225.0.0.50`);
    lines.push(`        Group 3780`);
    lines.push(`        IPv4_interface ${localIp}`);
    lines.push(`        Interface ${sync.interface}`);
    lines.push('        SndSocketBuffer 12492800');
    lines.push('        RcvSocketBuffer 12492800');
    lines.push('        Checksum on');
    lines.push('    }');
  } else {
    // Unicast UDP
    lines.push('    UDP {');
    lines.push(`        IPv4_address ${localIp}`);
    lines.push(`        IPv4_Destination_Address ${sync.peerAddress || ha.peerAddress || '192.168.1.2'}`);
    lines.push(`        Port ${sync.port}`);
    lines.push(`        Interface ${sync.interface}`);
    lines.push('        SndSocketBuffer 12492800');
    lines.push('        RcvSocketBuffer 12492800');
    lines.push('        Checksum on');
    lines.push('    }');
  }

  lines.push('}');
  lines.push('');

  lines.push('General {');
  lines.push('    Nice -20');
  lines.push('    HashSize 32768');
  lines.push('    HashLimit 131072');
  lines.push('    LogFile /var/log/conntrackd.log');
  lines.push('    Syslog on');
  lines.push('    LockFile /var/lock/conntrackd.lock');
  lines.push('    UNIX {');
  lines.push('        Path /var/run/conntrackd.ctl');
  lines.push('        Backlog 20');
  lines.push('    }');
  lines.push('    Filter From Userspace {');
  lines.push('        Protocol Accept {');
  lines.push('            TCP');
  lines.push('            UDP');
  lines.push('        }');
  lines.push('        Address Ignore {');
  lines.push('            IPv4_address 127.0.0.1');
  lines.push('        }');
  lines.push('    }');
  lines.push('}');

  return lines.join('\n');
}

/**
 * Filters DesiredState for mTLS replication according to the selected HaSyncSections.
 */
export function filterHaSyncState(state: DesiredState, sync: HaSyncSections): Partial<DesiredState> {
  const filtered: Partial<DesiredState> = {
    version: state.version,
  };

  if (sync.firewall) {
    filtered.rules = state.rules;
    filtered.nat = state.nat;
  }

  if (sync.aliases) {
    filtered.aliases = state.aliases;
  }

  if (sync.dhcp) {
    filtered.dhcp = state.dhcp;
  }

  if (sync.dns) {
    filtered.dns = state.dns;
  }

  if (sync.vpn) {
    filtered.wireguard = state.wireguard;
    filtered.ipsec = state.ipsec;
    filtered.openvpn = state.openvpn;
  }

  if (sync.interfaces) {
    filtered.interfaces = state.interfaces;
    filtered.vlans = state.vlans;
    filtered.bridges = state.bridges;
    filtered.bonds = state.bonds;
    filtered.virtualIps = state.virtualIps;
    filtered.gateways = state.gateways;
    filtered.gatewayGroups = state.gatewayGroups;
  }

  return filtered;
}

/**
 * Compiles ISC Kea DHCPv4 HA hook configuration block.
 */
export function compileKeaHaHook(ha: HighAvailabilityConfig, localIp: string): Record<string, any> | null {
  if (!ha.enabled) return null;

  const isPrimary = ha.nodeRole === 'master';
  return {
    library: '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so',
    parameters: {
      'high-availability': [
        {
          'this-server-name': isPrimary ? 'axon-primary' : 'axon-secondary',
          mode: 'hot-standby',
          'heartbeat-delay': 10000,
          'max-response-delay': 60000,
          'max-ack-delay': 5000,
          'max-unacked-clients': 10,
          peers: [
            {
              name: 'axon-primary',
              url: `http://${isPrimary ? localIp : ha.peerAddress}:8001/`,
              role: 'primary',
              auto_failover: true,
            },
            {
              name: 'axon-secondary',
              url: `http://${!isPrimary ? localIp : ha.peerAddress}:8001/`,
              role: 'standby',
              auto_failover: true,
            },
          ],
        },
      ],
    },
  };
}
