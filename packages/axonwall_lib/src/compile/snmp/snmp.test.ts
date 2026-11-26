import { describe, it, expect } from 'vitest';
import { SnmpPluginConfigSchema } from '../../schemas/index.js';
import { compileSnmpd } from './index.js';

describe('SNMP Daemon Compiler (v2c & v3)', () => {
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

  it('compiles SNMPv3 authPriv without leaking v2c rocommunity', () => {
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
    expect(conf).toContain('createUser librenms SHA-256 "supersecretauthpass" AES "supersecretprivpass"');
    expect(conf).toContain('rouser librenms priv -V all');
  });
});
