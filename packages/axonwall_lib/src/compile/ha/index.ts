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

    lines.push('    notify_master "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -c; /usr/local/bin/axonwall-ha-notify MASTER"');
    lines.push('    notify_backup "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -f; /usr/local/bin/axonwall-ha-notify BACKUP"');
    lines.push('    notify_fault  "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -t; /usr/local/bin/axonwall-ha-notify FAULT"');
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
  const mode = sync.mode || 'FTFW';
  const bufSize = sync.bufferSize || 12492800;

  lines.push('# conntrackd.conf - Axonwall High Availability State Synchronization');
  lines.push('Sync {');
  lines.push(`    Mode ${mode} {`);
  lines.push('        ResendQueueSize 131072');
  lines.push('        CommitTimeout 180');
  lines.push('        PurgeTimeout 60');
  lines.push('        ACKWindowSize 300');
  lines.push('    }');
  lines.push('');

  if (sync.protocol === 'multicast') {
    lines.push('    Multicast {');
    lines.push(`        IPv4_address ${sync.multicastGroup || '225.0.0.50'}`);
    lines.push(`        Group ${sync.port || 3780}`);
    lines.push(`        IPv4_interface ${localIp}`);
    lines.push(`        Interface ${sync.interface}`);
    lines.push(`        SndSocketBuffer ${bufSize}`);
    lines.push(`        RcvSocketBuffer ${bufSize}`);
    lines.push('        Checksum on');
    lines.push('    }');
  } else {
    // Unicast UDP
    lines.push('    UDP {');
    lines.push(`        IPv4_address ${localIp}`);
    lines.push(`        IPv4_Destination_Address ${sync.peerAddress || ha.peerAddress || '192.168.1.2'}`);
    lines.push(`        Port ${sync.port}`);
    lines.push(`        Interface ${sync.interface}`);
    lines.push(`        SndSocketBuffer ${bufSize}`);
    lines.push(`        RcvSocketBuffer ${bufSize}`);
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
  lines.push('            ICMP');
  lines.push('        }');
  lines.push('        Address Ignore {');
  lines.push('            IPv4_address 127.0.0.1');

  if (sync.filterIgnoreIps && sync.filterIgnoreIps.length > 0) {
    for (const ip of sync.filterIgnoreIps) {
      if (ip !== '127.0.0.1') {
        lines.push(`            IPv4_address ${ip}`);
      }
    }
  }

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

  if (sync.sqlite) {
    filtered.headscale = state.headscale;
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

/**
 * Compiles Litestream configuration (/etc/litestream.yml) for SQLite database replication.
 */
export function compileLitestreamConfig(ha: HighAvailabilityConfig): string {
  const sync = ha.sqliteSync ?? {
    enabled: false,
    mode: 'direct_stream' as const,
    databases: ['/var/lib/axonwall/headscale/db.sqlite'],
    syncIntervalSeconds: 5,
    listenPort: 9876,
  };
  const lines: string[] = [];

  lines.push('# /etc/litestream.yml - Managed by Axonwall High Availability');
  lines.push('# Documentation: https://litestream.io/reference/config/');
  lines.push('');
  lines.push('dbs:');

  for (const dbPath of sync.databases) {
    lines.push(`  - path: ${dbPath}`);
    lines.push('    replicas:');
    if (sync.litestreamBucket) {
      lines.push(`      - type: s3`);
      lines.push(`        bucket: ${sync.litestreamBucket}`);
      lines.push(`        path: ${dbPath.replace(/\//g, '_')}`);
      if (sync.litestreamEndpoint) {
        lines.push(`        endpoint: ${sync.litestreamEndpoint}`);
      }
      if (sync.litestreamAccessKeyId) {
        lines.push(`        access-key-id: ${sync.litestreamAccessKeyId}`);
      }
      if (sync.litestreamSecretAccessKey) {
        lines.push(`        secret-access-key: ${sync.litestreamSecretAccessKey}`);
      }
    } else {
      // Local/peer directory replica
      const replicaDir = dbPath.replace('.sqlite', '.replica');
      lines.push(`      - type: file`);
      lines.push(`        path: ${replicaDir}`);
    }
    lines.push(`        sync-interval: ${sync.syncIntervalSeconds}s`);
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Compiles native Axonwall SQLite sync daemon configuration (/etc/axonwall/sqlite_sync.json).
 */
export function compileSqliteSyncConfig(ha: HighAvailabilityConfig, localIp: string = '127.0.0.1'): Record<string, any> {
  const sync = ha.sqliteSync ?? {
    enabled: false,
    mode: 'direct_stream' as const,
    databases: ['/var/lib/axonwall/headscale/db.sqlite'],
    syncIntervalSeconds: 5,
    listenPort: 9876,
  };
  const isMaster = ha.nodeRole === 'master' && !ha.maintenanceMode;

  return {
    enabled: Boolean(sync.enabled && ha.enabled),
    nodeRole: isMaster ? 'master' : 'backup',
    mode: sync.mode,
    databases: sync.databases,
    syncIntervalSeconds: sync.syncIntervalSeconds,
    listenPort: sync.listenPort,
    peerAddress: sync.peerAddress || ha.peerAddress,
    peerPort: sync.peerPort || sync.listenPort,
    authToken: sync.authToken || ha.vrrpInstances?.[0]?.authPassword || '',
    localAddress: localIp,
    autoPromoteHeadscale: true,
    checkpointOnSync: true,
  };
}
