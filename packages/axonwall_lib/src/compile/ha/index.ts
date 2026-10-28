import type { HighAvailabilityConfig, DesiredState, HaSyncSections } from '../../schemas/index.js';

/**
 * Compiles keepalived VRRP configuration (/etc/keepalived/keepalived.conf).
 */
export function compileKeepalived(ha: HighAvailabilityConfig, hostname: string = 'axonwall'): string {
  const lines: string[] = [];
  const safeHostname = hostname.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '') || 'axonwall';

  lines.push('! Configuration File for keepalived (Axonwall Managed)');
  lines.push('');
  lines.push('global_defs {');
  lines.push(`    router_id ${safeHostname}`);
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
    const safeName = vrrp.name.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '');
    const safeInterface = vrrp.interface.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '');
    if (!safeName || !safeInterface) continue;

    const isMaster = ha.nodeRole === 'master' && !ha.maintenanceMode;
    // In maintenance mode, drop priority to lowest to force peer takeover
    const effectivePriority = ha.maintenanceMode ? 1 : Math.max(1, Math.min(255, Number(vrrp.priority) || 100));
    const safeVrid = Math.max(1, Math.min(255, Number(vrrp.vrid) || 1));

    lines.push(`vrrp_instance ${safeName} {`);
    lines.push(`    state ${isMaster ? 'MASTER' : 'BACKUP'}`);
    lines.push(`    interface ${safeInterface}`);
    lines.push(`    virtual_router_id ${safeVrid}`);
    lines.push(`    priority ${effectivePriority}`);
    lines.push('    advert_int 1');
    lines.push('    nopreempt');

    if (vrrp.authPassword) {
      const safePassword = vrrp.authPassword.split(/[\r\n]/)[0].trim().replace(/[\r\n\s]+/g, '').slice(0, 8);
      if (safePassword) {
        lines.push('    authentication {');
        lines.push('        auth_type PASS');
        lines.push(`        auth_pass ${safePassword}`);
        lines.push('    }');
      }
    }

    lines.push('    virtual_ipaddress {');
    for (const vip of vrrp.virtualIps) {
      const safeVip = vip.split(/[\r\n]/)[0].trim().replace(/[^a-fA-F0-9:./]/g, '');
      if (safeVip) {
        lines.push(`        ${safeVip}`);
      }
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
  const safeMode = sync.mode === 'NOTRACK' || sync.mode === 'ALARM' ? sync.mode : 'FTFW';
  const bufSize = Math.max(1024, Number(sync.bufferSize) || 12492800);
  const safeLocalIp = localIp.split(/[\r\n]/)[0].trim().replace(/[^a-fA-F0-9:.]/g, '') || '127.0.0.1';
  const safeInterface = sync.interface.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '');
  const safePort = Math.max(1, Math.min(65535, Number(sync.port) || 3780));

  lines.push('# conntrackd.conf - Axonwall High Availability State Synchronization');
  lines.push('Sync {');
  lines.push(`    Mode ${safeMode} {`);
  lines.push('        ResendQueueSize 131072');
  lines.push('        CommitTimeout 180');
  lines.push('        PurgeTimeout 60');
  lines.push('        ACKWindowSize 300');
  lines.push('    }');
  lines.push('');

  if (sync.protocol === 'multicast') {
    const safeMulticastGroup = (sync.multicastGroup || '225.0.0.50').split(/[\r\n]/)[0].trim().replace(/[^0-9.]/g, '');
    lines.push('    Multicast {');
    lines.push(`        IPv4_address ${safeMulticastGroup}`);
    lines.push(`        Group ${safePort}`);
    lines.push(`        IPv4_interface ${safeLocalIp}`);
    lines.push(`        Interface ${safeInterface}`);
    lines.push(`        SndSocketBuffer ${bufSize}`);
    lines.push(`        RcvSocketBuffer ${bufSize}`);
    lines.push('        Checksum on');
    lines.push('    }');
  } else {
    // Unicast UDP
    const rawPeer = (sync.peerAddress || ha.peerAddress || '192.168.1.2').split(/[\r\n]/)[0].trim();
    const safePeerAddress = rawPeer.replace(/[^a-fA-F0-9:.]/g, '');
    lines.push('    UDP {');
    lines.push(`        IPv4_address ${safeLocalIp}`);
    lines.push(`        IPv4_Destination_Address ${safePeerAddress}`);
    lines.push(`        Port ${safePort}`);
    lines.push(`        Interface ${safeInterface}`);
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
      const safeIp = ip.split(/[\r\n]/)[0].trim().replace(/[^a-fA-F0-9:.]/g, '');
      if (safeIp && safeIp !== '127.0.0.1') {
        lines.push(`            IPv4_address ${safeIp}`);
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

  if (state.capabilities) {
    filtered.capabilities = state.capabilities;
  }

  if (sync.nas !== false && state.nas) {
    filtered.nas = state.nas;
  }

  if (sync.k3s !== false && state.k3s) {
    filtered.k3s = state.k3s;
  }

  return filtered;
}

/**
 * Compiles ISC Kea DHCPv4 HA hook configuration block.
 */
export function compileKeaHaHook(ha: HighAvailabilityConfig, localIp: string): Record<string, any> | null {
  if (!ha.enabled) return null;

  const safePeer = (ha.peerAddress || '').trim();
  const safeLocal = (localIp || '').trim();
  const safeHostRegex = /^[a-zA-Z0-9.:-]+$/;
  if (!safePeer || !safeHostRegex.test(safePeer)) {
    throw new Error(`Invalid HA peerAddress for Kea HA hook: ${ha.peerAddress}`);
  }
  if (!safeLocal || !safeHostRegex.test(safeLocal)) {
    throw new Error(`Invalid localIp for Kea HA hook: ${localIp}`);
  }

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
              url: `http://${isPrimary ? safeLocal : safePeer}:8001/`,
              role: 'primary',
              auto_failover: true,
            },
            {
              name: 'axon-secondary',
              url: `http://${!isPrimary ? safeLocal : safePeer}:8001/`,
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
    transport: 'mtls' as const,
    requireSignedPayloads: false,
  };
  const lines: string[] = [];

  lines.push('# /etc/litestream.yml - Managed by Axonwall High Availability');
  lines.push('# Documentation: https://litestream.io/reference/config/');
  lines.push('');
  lines.push('dbs:');

  for (const dbPath of sync.databases) {
    const safeDbPath = (dbPath || '').replace(/[\r\n\0]/g, '').trim();
    if (!safeDbPath) continue;
    lines.push(`  - path: ${JSON.stringify(safeDbPath)}`);
    lines.push('    replicas:');
    if (sync.litestreamBucket) {
      const safeBucket = (sync.litestreamBucket || '').replace(/[\r\n\0]/g, '').trim();
      const safeS3Path = safeDbPath.replace(/\//g, '_');
      lines.push(`      - type: s3`);
      lines.push(`        bucket: ${JSON.stringify(safeBucket)}`);
      lines.push(`        path: ${JSON.stringify(safeS3Path)}`);
      if (sync.litestreamEndpoint) {
        const safeEndpoint = (sync.litestreamEndpoint || '').replace(/[\r\n\0]/g, '').trim();
        lines.push(`        endpoint: ${JSON.stringify(safeEndpoint)}`);
      }
      if (sync.litestreamAccessKeyId) {
        const safeKeyId = (sync.litestreamAccessKeyId || '').replace(/[\r\n\0]/g, '').trim();
        lines.push(`        access-key-id: ${JSON.stringify(safeKeyId)}`);
      }
      if (sync.litestreamSecretAccessKey) {
        const safeSecret = (sync.litestreamSecretAccessKey || '').replace(/[\r\n\0]/g, '').trim();
        lines.push(`        secret-access-key: ${JSON.stringify(safeSecret)}`);
      }
    } else {
      // Local/peer directory replica
      const replicaDir = safeDbPath.replace('.sqlite', '.replica');
      lines.push(`      - type: file`);
      lines.push(`        path: ${JSON.stringify(replicaDir)}`);
    }
    const safeInterval = Math.max(1, Math.min(86400, Number(sync.syncIntervalSeconds) || 5));
    lines.push(`        sync-interval: ${safeInterval}s`);
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
    transport: 'mtls' as const,
    requireSignedPayloads: false,
  };
  const isMaster = ha.nodeRole === 'master' && !ha.maintenanceMode;

  return {
    enabled: Boolean(sync.enabled && ha.enabled),
    nodeRole: isMaster ? 'master' : 'backup',
    mode: sync.mode,
    databases: sync.databases,
    syncIntervalSeconds: sync.syncIntervalSeconds,
    listenPort: sync.listenPort,
    transport: sync.transport,
    requireSignedPayloads: sync.requireSignedPayloads,
    peerAddress: sync.peerAddress || ha.peerAddress,
    peerPort: sync.peerPort || sync.listenPort,
    authToken: sync.authToken || ha.vrrpInstances?.[0]?.authPassword || '',
    localAddress: localIp,
    autoPromoteHeadscale: true,
    checkpointOnSync: true,
  };
}
