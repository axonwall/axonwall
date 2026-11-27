import { describe, it, expect } from 'vitest';
import { SnmpPluginConfigSchema, DesiredStateSchema } from '../../schemas/index.js';
import { compileSnmpd, compileSnmpdPersistentUsers } from './index.js';
import { compileNftables } from '../nft/index.js';

describe('SNMP Daemon Compiler (v2c & v3)', () => {
  it('defaults schema to SNMPv3, empty community, and loopback bind address', () => {
    const defaults = SnmpPluginConfigSchema.parse({});
    expect(defaults.version).toBe('v3');
    expect(defaults.community).toBe('');
    expect(defaults.bindAddresses).toEqual(['127.0.0.1']);

    const conf = compileSnmpd(defaults);
    expect(conf).toContain('agentAddress udp:127.0.0.1:161');
    expect(conf).not.toContain('rocommunity');
    expect(conf).not.toContain('public');
  });

  it('filters wildcard bind addresses (0.0.0.0 / ::) and falls back to loopback', () => {
    const cfg = SnmpPluginConfigSchema.parse({
      enabled: true,
      version: 'v3',
      bindAddresses: ['0.0.0.0', '::'],
    });
    const conf = compileSnmpd(cfg);
    expect(conf).toContain('agentAddress udp:127.0.0.1:161,udp6:[::1]:161');
  });

  it('compiles SNMPv2c without duplicate rocommunity lines and respects bindAddresses', () => {
    const cfg = SnmpPluginConfigSchema.parse({
      enabled: true,
      version: 'v2c',
      community: 'axon-ro',
      listenPort: 161,
      bindAddresses: ['10.8.0.1', '10.60.0.1'],
    });
    const conf = compileSnmpd(cfg);
    expect(conf).toContain('agentAddress udp:10.8.0.1:161,udp:10.60.0.1:161');
    const roMatches = conf.match(/^rocommunity /gm) ?? [];
    expect(roMatches).toHaveLength(1);
    expect(conf).toContain('rocommunity axon-ro default -V all');
  });

  it('compiles SNMPv3 authPriv without leaking v2c rocommunity or plaintext createUser in /etc/snmp/snmpd.conf', () => {
    const cfg = SnmpPluginConfigSchema.parse({
      enabled: true,
      version: 'v3',
      community: 'public',
      bindAddresses: ['10.8.0.1'],
      v3Users: [
        {
          username: 'librenms',
          authProtocol: 'SHA-256',
          authPassword: 'supersecretauthpass',
          privProtocol: 'AES',
          privPassword: 'supersecretprivpass',
          securityLevel: 'authPriv',
        },
      ],
    });
    const conf = compileSnmpd(cfg);
    expect(conf).not.toContain('rocommunity');
    expect(conf).not.toContain('createUser');
    expect(conf).not.toContain('supersecretauthpass');
    expect(conf).toContain('rouser librenms priv -V all');

    const persistentUsers = compileSnmpdPersistentUsers(cfg);
    expect(persistentUsers).toContain('createUser librenms SHA-256 "supersecretauthpass" AES "supersecretprivpass"');

    const bundle = compileNftables(DesiredStateSchema.parse({ snmp: cfg }));
    const etcSnmp = bundle.files.find((f) => f.path === '/etc/snmp/snmpd.conf');
    const varSnmp = bundle.files.find((f) => f.path === '/var/lib/snmp/snmpd.conf');
    expect(etcSnmp?.fileMode).toBe(0o640);
    expect(etcSnmp?.content).not.toContain('createUser');
    expect(varSnmp?.fileMode).toBe(0o600);
    expect(varSnmp?.content).toContain('createUser librenms SHA-256 "supersecretauthpass" AES "supersecretprivpass"');
  });
});
