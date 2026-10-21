import { describe, it, expect } from 'vitest';
import {
  compileKeepalived,
  compileConntrackd,
  compileKeaHaHook,
  compileLitestreamConfig,
  compileSqliteSyncConfig,
  filterHaSyncState,
} from './index.js';
import type { HighAvailabilityConfig, DesiredState } from '../../schemas/index.js';

describe('High Availability & Distributed SQLite Sync Compilers', () => {
  const baseHaConfig: HighAvailabilityConfig = {
    enabled: true,
    nodeRole: 'master',
    peerAddress: '10.0.99.2',
    peerPort: 2966,
    vrrpInstances: [
      {
        name: 'VI_LAN',
        interface: 'eth1',
        vrid: 51,
        priority: 100,
        virtualIps: ['192.168.1.1/24'],
        authPassword: 'secretpassword',
      },
    ],
    conntrackSync: {
      enabled: true,
      interface: 'eth3',
      protocol: 'unicast',
      peerAddress: '10.0.99.2',
      port: 3780,
    },
    sqliteSync: {
      enabled: true,
      mode: 'direct_stream',
      databases: ['/var/lib/axonwall/headscale/db.sqlite'],
      syncIntervalSeconds: 5,
      listenPort: 9876,
      transport: 'token-http',
      requireSignedPayloads: false,
      peerAddress: '10.0.99.2',
      peerPort: 9876,
      authToken: 'synctoken123',
    },
    syncSections: {
      interfaces: false,
      firewall: true,
      dhcp: true,
      dns: true,
      aliases: true,
      vpn: true,
      sqlite: true,
    },
    maintenanceMode: false,
  };

  it('compiles keepalived with axonwall-ha-notify hook', () => {
    const conf = compileKeepalived(baseHaConfig, 'axon-node-1');
    expect(conf).toContain('router_id axon-node-1');
    expect(conf).toContain('vrrp_instance VI_LAN');
    expect(conf).toContain('state MASTER');
    expect(conf).toContain('notify_master "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -c; /usr/local/bin/axonwall-ha-notify MASTER"');
    expect(conf).toContain('notify_backup "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -f; /usr/local/bin/axonwall-ha-notify BACKUP"');
    expect(conf).toContain('notify_fault  "/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf -t; /usr/local/bin/axonwall-ha-notify FAULT"');
  });

  it('compiles native Go SQLite sync daemon config', () => {
    const config = compileSqliteSyncConfig(baseHaConfig, '10.0.99.1');
    expect(config.enabled).toBe(true);
    expect(config.nodeRole).toBe('master');
    expect(config.mode).toBe('direct_stream');
    expect(config.databases).toEqual(['/var/lib/axonwall/headscale/db.sqlite']);
    expect(config.syncIntervalSeconds).toBe(5);
    expect(config.listenPort).toBe(9876);
    expect(config.peerAddress).toBe('10.0.99.2');
    expect(config.authToken).toBe('synctoken123');
    expect(config.transport).toBe('token-http');
    expect(config.localAddress).toBe('10.0.99.1');
    expect(config.autoPromoteHeadscale).toBe(true);
  });

  it('passes the mtls transport selection through to the daemon config (D-04 P1)', () => {
    const mtlsHaConfig: HighAvailabilityConfig = {
      ...baseHaConfig,
      sqliteSync: { ...baseHaConfig.sqliteSync, transport: 'mtls' },
    };
    const config = compileSqliteSyncConfig(mtlsHaConfig, '10.0.99.1');
    expect(config.transport).toBe('mtls');
  });

  it('passes requireSignedPayloads through to the daemon config (D-04 P2)', () => {
    const signedHaConfig: HighAvailabilityConfig = {
      ...baseHaConfig,
      sqliteSync: { ...baseHaConfig.sqliteSync, requireSignedPayloads: true },
    };
    const config = compileSqliteSyncConfig(signedHaConfig, '10.0.99.1');
    expect(config.requireSignedPayloads).toBe(true);
    expect(compileSqliteSyncConfig(baseHaConfig, '10.0.99.1').requireSignedPayloads).toBe(false);
  });

  it('compiles litestream config with s3 and directory replica targets', () => {
    const s3HaConfig: HighAvailabilityConfig = {
      ...baseHaConfig,
      sqliteSync: {
        ...baseHaConfig.sqliteSync,
        mode: 'litestream',
        litestreamBucket: 'axonwall-ha-backup',
        litestreamEndpoint: 'https://s3.eu-west-1.amazonaws.com',
        litestreamAccessKeyId: 'AKIA12345678',
        litestreamSecretAccessKey: 'SECRET98765432',
      },
    };

    const yml = compileLitestreamConfig(s3HaConfig);
    expect(yml).toContain('path: /var/lib/axonwall/headscale/db.sqlite');
    expect(yml).toContain('bucket: axonwall-ha-backup');
    expect(yml).toContain('endpoint: https://s3.eu-west-1.amazonaws.com');
    expect(yml).toContain('access-key-id: AKIA12345678');
    expect(yml).toContain('secret-access-key: SECRET98765432');
    expect(yml).toContain('sync-interval: 5s');
  });

  it('handles backup node role and maintenance mode correctly', () => {
    const backupConfig: HighAvailabilityConfig = {
      ...baseHaConfig,
      nodeRole: 'backup',
    };
    const sqliteConfig = compileSqliteSyncConfig(backupConfig);
    expect(sqliteConfig.nodeRole).toBe('backup');

    const maintConfig: HighAvailabilityConfig = {
      ...baseHaConfig,
      maintenanceMode: true,
    };
    const maintSqlite = compileSqliteSyncConfig(maintConfig);
    expect(maintSqlite.nodeRole).toBe('backup');

    const undefinedSyncConfig = {
      ...baseHaConfig,
      sqliteSync: undefined as any,
    };
    expect(() => compileLitestreamConfig(undefinedSyncConfig)).not.toThrow();
    expect(compileSqliteSyncConfig(undefinedSyncConfig).enabled).toBe(false);
  });
});
