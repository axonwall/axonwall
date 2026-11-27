import { describe, expect, it, vi, beforeEach } from 'vitest';

interface MockClientSpec {
  bind?: ReturnType<typeof vi.fn>;
  search?: ReturnType<typeof vi.fn>;
  startTLS?: ReturnType<typeof vi.fn>;
  unbind?: ReturnType<typeof vi.fn>;
}

const mockQueue: MockClientSpec[] = [];
const constructorCalls: Array<Record<string, unknown>> = [];
const instantiatedClients: Array<{
  bind: ReturnType<typeof vi.fn>;
  search: ReturnType<typeof vi.fn>;
  startTLS: ReturnType<typeof vi.fn>;
  unbind: ReturnType<typeof vi.fn>;
}> = [];

vi.mock('ldapts', () => ({
  Client: class MockLdapClient {
    bind: ReturnType<typeof vi.fn>;
    search: ReturnType<typeof vi.fn>;
    startTLS: ReturnType<typeof vi.fn>;
    unbind: ReturnType<typeof vi.fn>;
    constructor(opts: Record<string, unknown>) {
      constructorCalls.push(opts);
      const next = mockQueue.shift() ?? {};
      this.bind = next.bind ?? vi.fn().mockResolvedValue(undefined);
      this.search = next.search ?? vi.fn().mockResolvedValue({ searchEntries: [] });
      this.startTLS = next.startTLS ?? vi.fn().mockResolvedValue(undefined);
      this.unbind = next.unbind ?? vi.fn().mockResolvedValue(undefined);
      instantiatedClients.push(this);
    }
  },
}));

import { authenticateLdap, normalizeLdapDn } from './index.js';

describe('authenticateLdap fail-closed group resolution & TLS hardening (SEC-H19)', () => {
  beforeEach(() => {
    mockQueue.length = 0;
    constructorCalls.length = 0;
    instantiatedClients.length = 0;
  });

  const baseConfig = {
    url: 'ldap://127.0.0.1:389',
    baseDn: 'dc=example,dc=com',
    bindDn: 'cn=svc,dc=example,dc=com',
    bindPassword: 'svc-password',
    userSearchFilter: '(&(objectClass=inetOrgPerson)(uid={{username}}))',
    groupSearchFilter: '(&(objectClass=groupOfNames)(member={{userDn}}))',
  };

  it('matches full normalized group DNs and verifies suffix under groupBaseDn / ou=groups,<baseDn>', async () => {
    expect(normalizeLdapDn(' CN=FW-Admins , OU=Groups , DC=Example , DC=Com ')).toBe(
      'cn=fw-admins,ou=groups,dc=example,dc=com',
    );

    // 1. Valid CN under ou=groups,<baseDn>
    mockQueue.push(
      {
        search: vi.fn().mockResolvedValueOnce({
          searchEntries: [
            {
              dn: 'uid=alice,ou=users,dc=example,dc=com',
              cn: 'Alice',
              memberOf: ['CN=FW-Admins, OU=Groups, DC=example, DC=com'],
            },
          ],
        }),
      },
      {},
    );
    const resCnOk = await authenticateLdap(
      { ...baseConfig, groupRoleMap: { 'fw-admins': 'admin' } },
      'alice',
      'secret',
    );
    expect(resCnOk.success).toBe(true);
    expect(resCnOk.session?.roles).toEqual(['admin']);

    // 2. Spoofed CN outside ou=groups,<baseDn> or nested under uid=... must NOT match short CN key
    mockQueue.push(
      {
        search: vi.fn().mockResolvedValueOnce({
          searchEntries: [
            {
              dn: 'uid=mallory,ou=users,dc=example,dc=com',
              cn: 'Mallory',
              memberOf: [
                'cn=fw-admins,ou=rogue,dc=untrusted,dc=com',
                'uid=mallory,cn=fw-admins,ou=groups,dc=example,dc=com',
              ],
            },
          ],
        }),
      },
      {},
    );
    const resSpoofed = await authenticateLdap(
      { ...baseConfig, groupRoleMap: { 'fw-admins': 'admin' } },
      'mallory',
      'secret',
    );
    expect(resSpoofed.success).toBe(false);

    // 3. Explicit full normalized DN match works even in a custom container
    mockQueue.push(
      {
        search: vi.fn().mockResolvedValueOnce({
          searchEntries: [
            {
              dn: 'uid=bob,ou=users,dc=example,dc=com',
              cn: 'Bob',
              memberOf: ['CN=Security-Ops, OU=Custom, DC=example, DC=com'],
            },
          ],
        }),
      },
      {},
    );
    const resFullDn = await authenticateLdap(
      {
        ...baseConfig,
        groupRoleMap: { 'cn=security-ops,ou=custom,dc=example,dc=com': 'operator' },
      },
      'bob',
      'secret',
    );
    expect(resFullDn.success).toBe(true);
    expect(resFullDn.session?.roles).toEqual(['operator']);
  });

  it('falls back to groupSearchFilter under verified groupBaseDn and fails closed when unmapped unless allowUnmappedReadonly is true', async () => {
    // Fallback groupSearchFilter matches entry under ou=groups
    mockQueue.push(
      {
        search: vi
          .fn()
          .mockResolvedValueOnce({
            searchEntries: [{ dn: 'uid=alice,ou=users,dc=example,dc=com', cn: 'Alice', memberOf: [] }],
          })
          .mockResolvedValueOnce({
            searchEntries: [{ dn: 'cn=fw-admins,ou=groups,dc=example,dc=com', cn: 'fw-admins' }],
          }),
      },
      {},
    );
    const mapped = await authenticateLdap(
      { ...baseConfig, groupMapping: { 'fw-admins': 'admin' } },
      'alice',
      'secret',
    );
    expect(mapped.success).toBe(true);
    expect(mapped.session?.roles).toEqual(['admin']);
    expect(instantiatedClients[0]?.search).toHaveBeenNthCalledWith(
      2,
      'ou=groups,dc=example,dc=com',
      expect.objectContaining({ attributes: ['dn', 'cn'] }),
    );

    // Fail-closed even when groupRoleMap and groupMapping are BOTH omitted
    mockQueue.push(
      {
        search: vi.fn().mockResolvedValueOnce({
          searchEntries: [
            {
              dn: 'uid=guest,ou=users,dc=example,dc=com',
              cn: 'Guest',
              memberOf: ['cn=unmapped,ou=groups,dc=example,dc=com'],
            },
          ],
        }),
      },
      {},
    );
    const omittedMapFailClosed = await authenticateLdap(baseConfig, 'guest', 'secret');
    expect(omittedMapFailClosed.success).toBe(false);

    // Explicit allowUnmappedReadonly: true grants readonly
    mockQueue.push(
      {
        search: vi.fn().mockResolvedValueOnce({
          searchEntries: [
            {
              dn: 'uid=guest,ou=users,dc=example,dc=com',
              cn: 'Guest',
              memberOf: ['cn=unmapped,ou=groups,dc=example,dc=com'],
            },
          ],
        }),
      },
      {},
    );
    const optedInReadonly = await authenticateLdap(
      { ...baseConfig, allowUnmappedReadonly: true },
      'guest',
      'secret',
    );
    expect(optedInReadonly.success).toBe(true);
    expect(optedInReadonly.session?.roles).toEqual(['readonly']);
  });

  it('wires tlsOptions for ldaps:// and upgrades StartTLS before bind without passing tlsOptions to ldap:// constructor', async () => {
    const caPem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

    // ldaps:// passes tlsOptions with rejectUnauthorized: true + custom ca
    mockQueue.push(
      {
        search: vi.fn().mockResolvedValueOnce({
          searchEntries: [
            {
              dn: 'uid=alice,ou=users,dc=example,dc=com',
              cn: 'Alice',
              memberOf: ['cn=admins,ou=groups,dc=example,dc=com'],
            },
          ],
        }),
      },
      {},
    );
    const ldapsRes = await authenticateLdap(
      {
        ...baseConfig,
        url: 'ldaps://ldap.example.com:636',
        tlsOptions: { ca: caPem, rejectUnauthorized: true },
        groupRoleMap: { admins: 'admin' },
      },
      'alice',
      'secret',
    );
    expect(ldapsRes.success).toBe(true);
    expect(constructorCalls[0]?.tlsOptions).toEqual({ ca: caPem, rejectUnauthorized: true });
    expect(constructorCalls[1]?.tlsOptions).toEqual({ ca: caPem, rejectUnauthorized: true });

    // StartTLS on ldap:// calls startTLS() before bind() and omits tlsOptions from constructor
    constructorCalls.length = 0;
    instantiatedClients.length = 0;
    const svcStartTls = vi.fn().mockResolvedValue(undefined);
    const svcBind = vi.fn().mockResolvedValue(undefined);
    const usrStartTls = vi.fn().mockResolvedValue(undefined);
    const usrBind = vi.fn().mockResolvedValue(undefined);
    mockQueue.push(
      {
        startTLS: svcStartTls,
        bind: svcBind,
        search: vi.fn().mockResolvedValueOnce({
          searchEntries: [
            {
              dn: 'uid=alice,ou=users,dc=example,dc=com',
              cn: 'Alice',
              memberOf: ['cn=admins,ou=groups,dc=example,dc=com'],
            },
          ],
        }),
      },
      {
        startTLS: usrStartTls,
        bind: usrBind,
      },
    );
    const startTlsRes = await authenticateLdap(
      {
        ...baseConfig,
        url: 'ldap://ldap.example.com:389',
        startTls: true,
        tlsOptions: { ca: caPem },
        groupRoleMap: { admins: 'admin' },
      },
      'alice',
      'secret',
    );
    expect(startTlsRes.success).toBe(true);
    expect(constructorCalls[0]?.tlsOptions).toBeUndefined();
    expect(constructorCalls[1]?.tlsOptions).toBeUndefined();
    expect(svcStartTls).toHaveBeenCalledWith({ ca: caPem, rejectUnauthorized: true });
    expect(usrStartTls).toHaveBeenCalledWith({ ca: caPem, rejectUnauthorized: true });
    expect(svcStartTls.mock.invocationCallOrder[0]!).toBeLessThan(svcBind.mock.invocationCallOrder[0]!);
    expect(usrStartTls.mock.invocationCallOrder[0]!).toBeLessThan(usrBind.mock.invocationCallOrder[0]!);
  });
});
