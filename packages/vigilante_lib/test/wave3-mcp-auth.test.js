import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

import * as jose from 'jose';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import {
  initOwner,
  addPrincipal,
  createSession,
  resolvePrincipalBySession,
  revokeSession,
  invalidateAuthzCache
} from '../src/engine/authz.js';
import {
  verifyOidcToken,
  resetOidcCache,
  createPinnedOidcFetch
} from '../src/engine/authz-oidc.js';
import {
  DEFAULT_ROLE_MAPPING,
  MAX_LDAP_BUFFER_BYTES,
  MinimalLdapSession,
  authenticateLdapUser,
  mapLdapGroupsToRole,
  normalizeLdapDn,
  parseLdapTarget,
  resolveVigilanteLdapConfig
} from '../src/engine/authz-ldap.js';
import {
  assertSafeLiveContainerPid,
  scanProcessMemory
} from '../src/engine/yarascan.js';
import { OpenVASModule } from '../src/modules/openvas/index.js';
import {
  createVigilanteMcpServer,
  MCP_TOOL_POLICIES,
  resolveMcpToolPolicy,
  resolveMcpResourcePolicy
} from '../src/mcp/server.js';
import { getVigilanteAuthzFile } from '../src/engine/config.js';
import { closeDataLake } from '../src/engine/datalake.js';

// ---------------------------------------------------------------------------
// Minimal ASN.1 BER helpers for mock LDAPv3 server tests
// ---------------------------------------------------------------------------
function berLen(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function berEl(tag, payload) {
  const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([Buffer.from([tag]), berLen(buf.length), buf]);
}
function berInt(val) {
  if (val === 0) return berEl(0x02, Buffer.from([0]));
  const bytes = [];
  let n = val;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  if (bytes[0] & 0x80) bytes.unshift(0x00);
  return berEl(0x02, Buffer.from(bytes));
}
function berEnum(val) {
  return berEl(0x0a, Buffer.from([val & 0xff]));
}
function berStr(str) {
  return berEl(0x04, Buffer.from(str, 'utf8'));
}
function berSeq(items) {
  return berEl(0x30, Buffer.concat(items));
}
function berSet(items) {
  return berEl(0x31, Buffer.concat(items));
}
function berLdapMsg(msgId, opEl) {
  return berSeq([berInt(msgId), opEl]);
}
function berBindResponse(msgId, resultCode = 0, diagnostic = '') {
  return berLdapMsg(
    msgId,
    berEl(0x61, Buffer.concat([berEnum(resultCode), berStr(''), berStr(diagnostic)]))
  );
}
function berSearchEntry(msgId, dn, attrs = {}) {
  const attrSeqs = Object.entries(attrs).map(([k, vals]) =>
    berSeq([berStr(k), berSet(vals.map(v => berStr(v)))])
  );
  return berLdapMsg(
    msgId,
    berEl(0x64, Buffer.concat([berStr(dn), berSeq(attrSeqs)]))
  );
}
function berSearchDone(msgId, resultCode = 0) {
  return berLdapMsg(
    msgId,
    berEl(0x65, Buffer.concat([berEnum(resultCode), berStr(''), berStr('')]))
  );
}
function readBerFrame(buf) {
  if (buf.length < 2) return null;
  let lenBytes = 1;
  let len = buf[1];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (buf.length < 2 + n) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[2 + i];
    lenBytes = 1 + n;
  }
  const total = 1 + lenBytes + len;
  if (buf.length < total) return null;
  // Extract messageId from first child INTEGER
  const body = buf.subarray(1 + lenBytes, total);
  const msgIdLen = body[1];
  let msgId = 0;
  for (let i = 0; i < msgIdLen; i++) msgId = (msgId << 8) | body[2 + i];
  const opTag = body[2 + msgIdLen];
  return { total, msgId, opTag, raw: buf.subarray(0, total) };
}

let tempRoot;
let prevEnv = {};

function saveEnv(keys) {
  for (const k of keys) {
    prevEnv[k] = process.env[k];
  }
}
function restoreEnv() {
  for (const [k, v] of Object.entries(prevEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

before(async () => {
  tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-w3-mcp-auth-'));
  saveEnv([
    'VIGILANTE_CONFIG_DIR',
    'XDG_CONFIG_HOME',
    'VIGILANTE_AUTHZ',
    'VIGILANTE_AUTHZ_FILE',
    'VIGILANTE_MCP_TOKEN',
    'VIGILANTE_MCP_ALLOW_WRITE',
    'VIGILANTE_CLI_ADMIN',
    'VIGILANTE_OIDC_ISSUER',
    'VIGILANTE_OIDC_CLIENT_ID',
    'VIGILANTE_LDAP_DEFAULT_ROLE',
    'VIGILANTE_SNAPSHOT_KEY'
  ]);
  process.env.VIGILANTE_CONFIG_DIR = path.join(tempRoot, 'cfg');
  process.env.XDG_CONFIG_HOME = tempRoot;
  delete process.env.VIGILANTE_AUTHZ;
  delete process.env.VIGILANTE_AUTHZ_FILE;
  delete process.env.VIGILANTE_MCP_TOKEN;
  delete process.env.VIGILANTE_MCP_ALLOW_WRITE;
  delete process.env.VIGILANTE_CLI_ADMIN;
  delete process.env.VIGILANTE_LDAP_DEFAULT_ROLE;
  process.env.VIGILANTE_SNAPSHOT_KEY = 'w3-snapshot-sealing-test-key-0123456789';
});

after(async () => {
  closeDataLake();
  invalidateAuthzCache();
  resetOidcCache();
  restoreEnv();
  await fs.rm(tempRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 1. [SEC-M46] authz.js constant-time session comparison
// ---------------------------------------------------------------------------
describe('[SEC-M46] authz.js constant-time session resolution', () => {
  it('resolves valid sessions, rejects mismatched/non-string tokens, and revokes cleanly', async () => {
    const authzPath = path.join(tempRoot, 'authz-m46.yaml');
    const { principal: owner } = await initOwner({ name: 'm46-owner' }, authzPath);
    const { sessionToken } = await createSession(owner.id, authzPath);

    const { loadAuthzStore } = await import('../src/engine/authz.js');
    const loaded = loadAuthzStore(authzPath, { forceReload: true });
    assert.equal(loaded.state, 'ready');

    const ok = resolvePrincipalBySession(loaded.store, sessionToken);
    assert.equal(ok.principal?.id, owner.id);
    assert.equal(ok.expired, false);

    // Same-length near-match token must fail
    const flipped = sessionToken.slice(0, -1) + (sessionToken.endsWith('a') ? 'b' : 'a');
    assert.equal(resolvePrincipalBySession(loaded.store, flipped).principal, null);
    assert.equal(resolvePrincipalBySession(loaded.store, 'short').principal, null);
    assert.equal(resolvePrincipalBySession(loaded.store, null).principal, null);

    // Revoke and verify gone
    await revokeSession(sessionToken, authzPath);
    const afterRevoke = loadAuthzStore(authzPath, { forceReload: true });
    assert.equal(resolvePrincipalBySession(afterRevoke.store, sessionToken).principal, null);
  });
});

// ---------------------------------------------------------------------------
// 2. [SEC-M38] authz-oidc.js algorithm pinning, issuer presence, redirect & IP pinning
// ---------------------------------------------------------------------------
describe('[SEC-M38] authz-oidc.js hardening', () => {
  it('accepts valid RS256 token and rejects HS256 confusion, missing issuer, redirects, and DNS rebind', async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
    const publicJwk = await jose.exportJWK(publicKey);
    publicJwk.kid = 'k1';
    publicJwk.use = 'sig';
    publicJwk.alg = 'RS256';

    let mode = 'valid';
    let redirectTargetHits = 0;

    const redirectTarget = http.createServer((_req, res) => {
      redirectTargetHits++;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys: [publicJwk] }));
    });
    await new Promise(r => redirectTarget.listen(0, '127.0.0.1', r));
    const redirectPort = redirectTarget.address().port;

    const idp = http.createServer((req, res) => {
      const base = `http://127.0.0.1:${idp.address().port}`;
      if (req.url === '/.well-known/openid-configuration') {
        if (mode === 'redirect-discovery') {
          res.writeHead(302, { location: `http://127.0.0.1:${redirectPort}/redirected-discovery` });
          res.end();
          return;
        }
        if (mode === 'missing-issuer') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ jwks_uri: `${base}/jwks` }));
          return;
        }
        if (mode === 'empty-issuer') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ issuer: '   ', jwks_uri: `${base}/jwks` }));
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          issuer: base,
          jwks_uri: `${base}/jwks`
        }));
        return;
      }
      if (req.url === '/jwks') {
        if (mode === 'redirect-jwks') {
          res.writeHead(302, { location: `http://127.0.0.1:${redirectPort}/keys` });
          res.end();
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ keys: [publicJwk] }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise(r => idp.listen(0, '127.0.0.1', r));
    const port = idp.address().port;
    const issuerUrl = `http://127.0.0.1:${port}`;
    const store = {
      principals: [{ id: 'u1', name: 'alice', oidcSubject: 'alice-sub', disabled: false }]
    };

    try {
      process.env.VIGILANTE_OIDC_ISSUER = issuerUrl;
      process.env.VIGILANTE_OIDC_CLIENT_ID = 'vigilante-cli';

      const validJwt = await new jose.SignJWT({ sub: 'alice-sub' })
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .setIssuedAt()
        .setIssuer(issuerUrl)
        .setAudience('vigilante-cli')
        .setExpirationTime('5m')
        .sign(privateKey);

      // 1. Valid RS256 JWT succeeds
      resetOidcCache();
      const matched = await verifyOidcToken(validJwt, store);
      assert.equal(matched?.id, 'u1');

      // 2. HS256 algorithm confusion fails closed
      const hmacSecret = new TextEncoder().encode(JSON.stringify(publicJwk));
      const hs256Jwt = await new jose.SignJWT({ sub: 'alice-sub' })
        .setProtectedHeader({ alg: 'HS256', kid: 'k1' })
        .setIssuedAt()
        .setIssuer(issuerUrl)
        .setAudience('vigilante-cli')
        .setExpirationTime('5m')
        .sign(hmacSecret);
      assert.equal(await verifyOidcToken(hs256Jwt, store), null);

      // 3. Missing or empty discovery.issuer fails closed
      for (const badMode of ['missing-issuer', 'empty-issuer']) {
        mode = badMode;
        resetOidcCache();
        assert.equal(await verifyOidcToken(validJwt, store), null);
      }

      // 4. Discovery redirect is blocked (redirect: 'error')
      mode = 'redirect-discovery';
      resetOidcCache();
      assert.equal(await verifyOidcToken(validJwt, store), null);
      assert.equal(redirectTargetHits, 0);

      // 5. JWKS redirect is blocked via [jose.customFetch]
      mode = 'redirect-jwks';
      resetOidcCache();
      assert.equal(await verifyOidcToken(validJwt, store), null);
      assert.equal(redirectTargetHits, 0);

      // 6. Direct createPinnedOidcFetch blocks DNS rebind to metadata IP and enforces redirect/size caps
      const rebindFetch = createPinnedOidcFetch({
        allowLoopback: false,
        label: 'jwks_uri',
        dnsLookup: async () => [{ address: '169.254.169.254', family: 4 }]
      });
      await assert.rejects(
        rebindFetch('https://idp.rebind.example/jwks'),
        /Blocked SSRF/
      );

      // 7. ES256 signed JWT also works under ALLOWED_OIDC_ALGORITHMS
      const { publicKey: ecPub, privateKey: ecPriv } = await jose.generateKeyPair('ES256');
      const ecJwk = await jose.exportJWK(ecPub);
      ecJwk.kid = 'ec1';
      ecJwk.use = 'sig';
      ecJwk.alg = 'ES256';
      publicJwk.kid = 'k1';
      const prevKeys = [publicJwk, ecJwk];
      mode = 'valid';
      // Serve both keys from /jwks temporarily via custom server
      const ecIdp = http.createServer((req, res) => {
        const b = `http://127.0.0.1:${ecIdp.address().port}`;
        if (req.url === '/.well-known/openid-configuration') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ issuer: b, jwks_uri: `${b}/jwks` }));
        } else {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ keys: prevKeys }));
        }
      });
      await new Promise(r => ecIdp.listen(0, '127.0.0.1', r));
      try {
        const ecIss = `http://127.0.0.1:${ecIdp.address().port}`;
        process.env.VIGILANTE_OIDC_ISSUER = ecIss;
        const es256Jwt = await new jose.SignJWT({ sub: 'alice-sub' })
          .setProtectedHeader({ alg: 'ES256', kid: 'ec1' })
          .setIssuedAt()
          .setIssuer(ecIss)
          .setAudience('vigilante-cli')
          .setExpirationTime('5m')
          .sign(ecPriv);
        resetOidcCache();
        assert.equal((await verifyOidcToken(es256Jwt, store))?.id, 'u1');
      } finally {
        ecIdp.close();
      }
    } finally {
      idp.close();
      redirectTarget.close();
      resetOidcCache();
    }
  });
});

// ---------------------------------------------------------------------------
// 3. [SEC-M39] authz-ldap.js fail-closed defaults, full DN, ambiguity, buffer cap, msgId, URI
// ---------------------------------------------------------------------------
describe('[SEC-M39] authz-ldap.js hardening', () => {
  it('defaults defaultRole to null and rejects bare cn= spoofing outside groupSearchBase', () => {
    const cfg = resolveVigilanteLdapConfig();
    assert.equal(cfg.defaultRole, null);

    // Zero mapped groups -> null (fail closed)
    assert.equal(mapLdapGroupsToRole(['unmapped-group']), null);

    // Spoofed memberOf DN without matching groupSearchBase must return null
    assert.equal(
      mapLdapGroupsToRole(['cn=axonwall-admin,ou=evil,dc=other,dc=com'], DEFAULT_ROLE_MAPPING),
      null
    );
    assert.equal(
      mapLdapGroupsToRole(
        ['cn=axonwall-admin,ou=evil,dc=axonwall,dc=local'],
        DEFAULT_ROLE_MAPPING,
        null,
        { groupSearchBase: 'ou=groups,dc=axonwall,dc=local', requireDn: true }
      ),
      null
    );
    // Escaped comma inside a single RDN value must NOT spoof groupSearchBase suffix
    assert.equal(
      mapLdapGroupsToRole(
        ['cn=evil\\,ou=groups,dc=axonwall,dc=local'],
        DEFAULT_ROLE_MAPPING,
        null,
        { groupSearchBase: 'ou=groups,dc=axonwall,dc=local', requireDn: true }
      ),
      null
    );
    assert.equal(
      mapLdapGroupsToRole(
        ['cn=axonwall-admin,ou=sub\\,ou=groups,dc=axonwall,dc=local'],
        DEFAULT_ROLE_MAPPING,
        null,
        { groupSearchBase: 'ou=groups,dc=axonwall,dc=local', requireDn: true }
      ),
      null
    );
    assert.equal(
      mapLdapGroupsToRole(
        ['cn=axonwall-admin\\,ou=evil,ou=groups,dc=axonwall,dc=local'],
        DEFAULT_ROLE_MAPPING,
        null,
        { groupSearchBase: 'ou=groups,dc=axonwall,dc=local', requireDn: true }
      ),
      null
    );

    // Verified DN under groupSearchBase matches
    assert.equal(
      mapLdapGroupsToRole(
        ['CN=Axonwall-Admin, OU=Groups, DC=Axonwall, DC=Local'],
        DEFAULT_ROLE_MAPPING,
        null,
        { groupSearchBase: 'ou=groups,dc=axonwall,dc=local', requireDn: true }
      ),
      'owner'
    );

    // Explicit full normalized DN mapping matches regardless of casing/spacing
    assert.equal(
      mapLdapGroupsToRole(
        ['CN=Sec-Ops, OU=Security, DC=Corp, DC=Local'],
        { adminGroups: ['cn=sec-ops,ou=security,dc=corp,dc=local'] },
        null,
        { requireDn: true }
      ),
      'admin'
    );
    assert.equal(normalizeLdapDn('CN=Sec-Ops, OU=Security, DC=Corp'), 'cn=sec-ops,ou=security,dc=corp');
  });

  it('validates LDAP URI scheme, embedded credentials, paths, and SSRF targets', () => {
    assert.throws(() => parseLdapTarget('http://127.0.0.1:389'), /scheme must be ldap:\/\/ or ldaps:\/\//);
    assert.throws(() => parseLdapTarget('127.0.0.1:389'), /scheme must be ldap:\/\/ or ldaps:\/\//);
    assert.throws(() => parseLdapTarget('ldap://user:pass@127.0.0.1:389'), /credentials/);
    assert.throws(() => parseLdapTarget('ldap://127.0.0.1:389/dc=evil'), /path/);
    assert.throws(() => parseLdapTarget('ldap://169.254.169.254:389'), /Blocked SSRF/);
    assert.throws(() => parseLdapTarget('ldap://[fd00:ec2::254]:389'), /Blocked SSRF/);
    assert.throws(() => parseLdapTarget('ldap://metadata.google.internal:389'), /Blocked SSRF/);
    assert.throws(
      () => resolveVigilanteLdapConfig({ enabled: true, uri: 'https://evil.example' }),
      /scheme must be ldap:\/\/ or ldaps:\/\//
    );

    const ok = parseLdapTarget('ldaps://ldap.internal.corp:636');
    assert.equal(ok.isTls, true);
    assert.equal(ok.port, 636);
  });

  it('rejects ambiguous user searches, enforces memberOf DN base, checks messageId, and caps socket buffer', async () => {
    let scenario = 'valid';
    const server = net.createServer((sock) => {
      let buf = Buffer.alloc(0);
      sock.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        while (true) {
          const frame = readBerFrame(buf);
          if (!frame) break;
          buf = buf.subarray(frame.total);

          if (frame.opTag === 0x60) {
            if (scenario === 'wrong-msgid') {
              sock.write(berBindResponse(frame.msgId + 42, 0));
              continue;
            }
            if (scenario === 'oversize-buffer') {
              // Send a chunk larger than configured maxBufferBytes
              sock.write(Buffer.alloc(2048, 0x30));
              continue;
            }
            sock.write(berBindResponse(frame.msgId, 0));
          } else if (frame.opTag === 0x63) {
            const rawText = frame.raw.toString('utf8');
            const isUserSearch = rawText.includes('memberOf') || rawText.includes('alice');
            if (isUserSearch) {
              if (scenario === 'ambiguous') {
                sock.write(berSearchEntry(frame.msgId, 'uid=alice,ou=users,dc=axonwall,dc=local', { uid: ['alice'] }));
                sock.write(berSearchEntry(frame.msgId, 'uid=alice2,ou=users,dc=axonwall,dc=local', { uid: ['alice'] }));
                sock.write(berSearchDone(frame.msgId, 0));
              } else if (scenario === 'spoofed-memberof') {
                sock.write(
                  berSearchEntry(frame.msgId, 'uid=alice,ou=users,dc=axonwall,dc=local', {
                    uid: ['alice'],
                    memberOf: ['cn=axonwall-admin,ou=evil,dc=other,dc=com']
                  })
                );
                sock.write(berSearchDone(frame.msgId, 0));
              } else {
                sock.write(
                  berSearchEntry(frame.msgId, 'uid=alice,ou=users,dc=axonwall,dc=local', {
                    uid: ['alice'],
                    cn: ['Alice'],
                    memberOf: [
                      'cn=axonwall-admin,ou=evil,dc=other,dc=com',
                      'CN=Axonwall-Operator, OU=Groups, DC=Axonwall, DC=Local'
                    ]
                  })
                );
                sock.write(berSearchDone(frame.msgId, 0));
              }
            } else {
              // Group search returns no extra POSIX groups
              sock.write(berSearchDone(frame.msgId, 0));
            }
          }
        }
      });
    });

    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    const baseCfg = {
      enabled: true,
      uri: `ldap://127.0.0.1:${port}`,
      baseDN: 'dc=axonwall,dc=local',
      bindDN: 'cn=svc,dc=axonwall,dc=local',
      bindPassword: 'svc-password',
      userSearchBase: 'ou=users,dc=axonwall,dc=local',
      groupSearchBase: 'ou=groups,dc=axonwall,dc=local',
      timeoutMs: 1500
    };

    try {
      // 1. Ambiguous user search (2 entries) is rejected
      scenario = 'ambiguous';
      const ambig = await authenticateLdapUser('alice', 'user-pass', baseCfg);
      assert.equal(ambig.ok, false);
      assert.equal(ambig.code, 'AMBIGUOUS_USER');

      // 2. Spoofed memberOf outside groupSearchBase grants NO role (defaultRole=null -> NO_MAPPED_ROLE)
      scenario = 'spoofed-memberof';
      const spoofed = await authenticateLdapUser('alice', 'user-pass', baseCfg);
      assert.equal(spoofed.ok, false);
      assert.equal(spoofed.code, 'NO_MAPPED_ROLE');

      // 3. Valid group DN under groupSearchBase maps to operator (ignores spoofed evil owner DN!)
      scenario = 'valid';
      const validRes = await authenticateLdapUser('alice', 'user-pass', baseCfg);
      assert.equal(validRes.ok, true);
      assert.equal(validRes.role, 'operator');
      assert.ok(validRes.groups.includes('cn=axonwall-operator,ou=groups,dc=axonwall,dc=local'));

      // 4. Mismatched messageId fails immediately
      scenario = 'wrong-msgid';
      const badMsgId = new MinimalLdapSession(baseCfg.uri, 1500, true);
      await badMsgId.connect();
      await assert.rejects(badMsgId.bind('cn=svc,dc=axonwall,dc=local', 'pw'), /messageId correlation mismatch/i);
      badMsgId.close();

      // 5. Max socket buffer cap enforced
      scenario = 'oversize-buffer';
      assert.equal(MAX_LDAP_BUFFER_BYTES, 1024 * 1024);
      const cappedSession = new MinimalLdapSession(baseCfg.uri, 1500, true, { maxBufferBytes: 1024 });
      await cappedSession.connect();
      await assert.rejects(cappedSession.bind('cn=svc,dc=axonwall,dc=local', 'pw'), /buffer exceeded maximum/i);
      cappedSession.close();
    } finally {
      server.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 4. [SEC-C06] MCP Auth, RBAC, OpenVAS & YARA/Snapshot PID protections
// ---------------------------------------------------------------------------
describe('[SEC-C06] Vigilante MCP auth, RBAC, OpenVAS & live proc gating', () => {
  it('OpenVASModule.status() never exposes credentials', async () => {
    const mod = new OpenVASModule();
    const st = await mod.status({ clusterName: 'nonexistent-cluster-9999', namespace: 'openvas' });
    assert.equal('credentials' in st, false);
    assert.equal(st.id, 'openvas');
  });

  it('maps every tool in server.js and populates target { module, namespace, clusterName }', () => {
    assert.ok(Object.keys(MCP_TOOL_POLICIES).length >= 100);
    const credPolicy = resolveMcpToolPolicy('get_openvas_credentials', {
      namespace: 'openvas-prod',
      clusterName: 'prod-k3d'
    });
    assert.equal(credPolicy.permission, 'cluster:write');
    assert.equal(credPolicy.requireAuth, true);
    assert.equal(credPolicy.target.module, 'openvas');
    assert.equal(credPolicy.target.namespace, 'openvas-prod');
    assert.equal(credPolicy.target.clusterName, 'prod-k3d');

    const hashesPolicy = resolveMcpResourcePolicy('vigilante://oob/hashes');
    assert.equal(hashesPolicy.permission, 'scans:run');
    assert.equal(hashesPolicy.requireAuth, true);
    assert.equal(hashesPolicy.target.module, 'oobscan');
  });

  it('forbids live /proc access on process.pid, PID 1, ppid, and host processes', async () => {
    await assert.rejects(assertSafeLiveContainerPid(process.pid), /own process/i);
    await assert.rejects(assertSafeLiveContainerPid(1), /host init/i);
    if (process.ppid > 1) {
      await assert.rejects(assertSafeLiveContainerPid(process.ppid), /host init or parent/i);
    }
    await assert.rejects(scanProcessMemory(process.pid, []), /own process/i);

    // Spawn a real non-container host child process and verify it is blocked
    const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], { stdio: 'ignore' });
    try {
      await new Promise(r => setTimeout(r, 50));
      await assert.rejects(
        scanProcessMemory(child.pid, []),
        /non-container or host-sensitive process/i
      );
    } finally {
      child.kill('SIGKILL');
    }
  });

  it('enforces fail-closed authz, RBAC scopes, write gating, and resource gating over MCP transport', async () => {
    const prevAuthzFile = process.env.VIGILANTE_AUTHZ_FILE;
    const mcpAuthzFile = path.join(tempRoot, 'mcp-authz.yaml');
    process.env.VIGILANTE_AUTHZ_FILE = mcpAuthzFile;
    invalidateAuthzCache();

    const server = createVigilanteMcpServer();
    const client = new Client({ name: 'w3-test-client', version: '1.0.0' }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    try {
      // A. Unconfigured store (no principals yet):
      //    - Legitimate read-only works
      //    - Sensitive secrets (get_openvas_credentials, vigilante://oob/hashes) fail closed even with VIGILANTE_CLI_ADMIN=1
      //    - All scanners / write tools fail without VIGILANTE_MCP_ALLOW_WRITE=1
      delete process.env.VIGILANTE_MCP_TOKEN;
      delete process.env.VIGILANTE_MCP_ALLOW_WRITE;
      process.env.VIGILANTE_CLI_ADMIN = '1';

      const hostsRes = await client.callTool({ name: 'list_hosts', arguments: {} });
      assert.ok(hostsRes.content[0].text.includes('total'));
      const nistResource = await client.readResource({ uri: 'vigilante://nist/framework' });
      assert.ok(nistResource.contents[0].text.includes('NIST SP 800-61'));

      await assert.rejects(
        client.callTool({ name: 'get_openvas_credentials', arguments: {} }),
        /Access denied.*deny_unauthenticated/i
      );
      await assert.rejects(
        client.readResource({ uri: 'vigilante://oob/hashes' }),
        /Access denied.*deny_unauthenticated/i
      );

      for (const [writeTool, toolArgs] of [
        ['run_nmap_scan', { target: '198.51.100.1' }],
        ['run_oob_scan', { target: '198.51.100.1' }],
        ['run_openvas_scan', { host: '198.51.100.1' }],
        ['run_recon_scan', { target: '198.51.100.1' }],
        ['run_nuclei_scan', { target: 'https://example.com' }],
        ['run_trivy_audit', { target: 'alpine:3.19' }],
        ['run_kube_audit', { target: 'cluster' }],
        ['run_netexec_audit', { target: '198.51.100.1' }],
        ['run_zap_scan', { targetUrl: 'https://example.com' }],
        ['replay_pcap', { pcapFilePath: 'sample.pcap' }],
        ['run_diagnostic', { tool: 'ping', host: '198.51.100.1', network: '198.51.100.0/24' }],
        ['run_triage_capture', { network: '198.51.100.0/24', host: '198.51.100.1' }],
        ['ingest_bloodhound_data', { filePath: 'bh.json' }],
        ['generate_cloud_honeytoken', { provider: 'aws' }],
        ['export_rfc3161_evidence_pack', { caseNumber: 'C-1', evidenceItems: [] }],
        ['generate_mitre_report', {}],
        ['generate_kspm_scorecard', {}],
        ['run_dynamic_adversary_simulation', { attackGraph: {}, targetPrincipal: 'DA' }],
        ['query_security_datalake', { sql: 'SELECT 1' }],
        ['scan_process_yara', { pid: 999999, rule: 'rule t { strings: $a = "x" condition: $a }' }],
        ['capture_container_snapshot', { podName: 'web-pod', pid: 999999 }]
      ]) {
        await assert.rejects(
          client.callTool({ name: writeTool, arguments: toolArgs }),
          /Access denied.*VIGILANTE_MCP_ALLOW_WRITE=1/i,
          `${writeTool} must fail when VIGILANTE_MCP_ALLOW_WRITE!=1`
        );
      }

      // B. Corrupt authz.yaml -> fail closed on EVERYTHING (including read-only tools/resources)
      await fs.mkdir(path.dirname(mcpAuthzFile), { recursive: true });
      await fs.writeFile(mcpAuthzFile, 'not: [valid: authz: schema');
      invalidateAuthzCache();
      await assert.rejects(client.callTool({ name: 'list_hosts', arguments: {} }), /deny_invalid_store/i);
      await assert.rejects(client.readResource({ uri: 'vigilante://hosts' }), /deny_invalid_store/i);
      await fs.rm(mcpAuthzFile, { force: true });
      invalidateAuthzCache();

      // C. Configured store with owner, admin, operator, viewer, and scoped viewer
      const ownerRes = await initOwner({ name: 'w3-owner' }, mcpAuthzFile);
      const adminRes = await addPrincipal({ name: 'w3-admin', role: 'admin' }, mcpAuthzFile);
      const operatorRes = await addPrincipal({ name: 'w3-operator', role: 'operator' }, mcpAuthzFile);
      const viewerRes = await addPrincipal({ name: 'w3-viewer', role: 'viewer' }, mcpAuthzFile);
      const scopedCredReader = await addPrincipal(
        {
          name: 'w3-scoped',
          role: 'viewer',
          grants: [
            {
              permission: 'cluster:write',
              scope: { moduleId: 'openvas', namespace: 'openvas-a', clusterName: 'c-a' }
            }
          ]
        },
        mcpAuthzFile
      );

      // C1. Unauthenticated (no token) rejected on ALL tools and ALL resources
      delete process.env.VIGILANTE_MCP_TOKEN;
      await assert.rejects(client.callTool({ name: 'list_hosts', arguments: {} }), /deny_unauthenticated/i);
      await assert.rejects(client.readResource({ uri: 'vigilante://hosts' }), /deny_unauthenticated/i);
      await assert.rejects(client.readResource({ uri: 'vigilante://evidence' }), /deny_unauthenticated/i);
      await assert.rejects(client.readResource({ uri: 'vigilante://oob/hashes' }), /deny_unauthenticated/i);

      // C2. Viewer: allowed on read-only tools/resources & buffer-only YARA, denied on sensitive/run/write tools
      process.env.VIGILANTE_MCP_TOKEN = viewerRes.token;
      const viewerHosts = await client.readResource({ uri: 'vigilante://hosts' });
      assert.ok(viewerHosts.contents[0].text.includes('totalHosts'));
      const viewerEv = await client.readResource({ uri: 'vigilante://evidence' });
      assert.ok(viewerEv.contents[0].text);
      const yaraBuf = await client.callTool({
        name: 'scan_process_yara',
        arguments: {
          rule: 'rule Hit { strings: $s = "beacon" condition: $s }',
          bufferBase64: Buffer.from('hello beacon world').toString('base64')
        }
      });
      assert.equal(JSON.parse(yaraBuf.content[0].text).summary.yaraRulesMatched, 1);

      await assert.rejects(client.readResource({ uri: 'vigilante://oob/hashes' }), /deny_missing_grant/i);
      await assert.rejects(client.callTool({ name: 'get_openvas_credentials', arguments: {} }), /deny_missing_grant/i);

      process.env.VIGILANTE_MCP_ALLOW_WRITE = '1';
      await assert.rejects(
        client.callTool({ name: 'run_diagnostic', arguments: { tool: 'ping', host: '198.51.100.1' } }),
        /deny_missing_grant/i
      );
      await assert.rejects(
        client.callTool({ name: 'query_security_datalake', arguments: { sql: 'SELECT 1' } }),
        /deny_missing_grant/i
      );
      await assert.rejects(
        client.callTool({ name: 'generate_cloud_honeytoken', arguments: { provider: 'aws' } }),
        /deny_missing_grant/i
      );
      await assert.rejects(
        client.callTool({
          name: 'scan_process_yara',
          arguments: { pid: 999999, rule: 'rule Hit { strings: $s = "x" condition: $s }' }
        }),
        /deny_missing_grant/i
      );
      await assert.rejects(
        client.callTool({ name: 'capture_container_snapshot', arguments: { podName: 'p', pid: 999999 } }),
        /deny_missing_grant/i
      );

      // C3. Operator: denied on admin-only get_openvas_credentials, allowed on vigilante://oob/hashes & forensics:run
      process.env.VIGILANTE_MCP_TOKEN = operatorRes.token;
      await assert.rejects(
        client.callTool({ name: 'get_openvas_credentials', arguments: {} }),
        /deny_missing_grant/i
      );
      const hashesRes = await client.readResource({ uri: 'vigilante://oob/hashes' });
      assert.equal(hashesRes.contents[0].mimeType, 'text/plain');

      // C4. Scoped grant enforces { moduleId, namespace, clusterName }
      process.env.VIGILANTE_MCP_TOKEN = scopedCredReader.token;
      await assert.rejects(
        client.callTool({
          name: 'get_openvas_credentials',
          arguments: { namespace: 'other-ns', clusterName: 'c-a' }
        }),
        /deny_missing_grant/i
      );
      // Matching scope clears authz (reaches kubectl secret lookup -> not found when cluster offline)
      const scopedOk = await client.callTool({
        name: 'get_openvas_credentials',
        arguments: { namespace: 'openvas-a', clusterName: 'c-a' }
      });
      assert.doesNotMatch(scopedOk.content[0].text, /Access denied/i);

      // C5. Admin clears get_openvas_credentials authz even without VIGILANTE_CLI_ADMIN
      delete process.env.VIGILANTE_CLI_ADMIN;
      process.env.VIGILANTE_MCP_TOKEN = adminRes.token;
      const adminCredCall = await client.callTool({ name: 'get_openvas_credentials', arguments: {} });
      assert.doesNotMatch(adminCredCall.content[0].text, /Access denied/i);

      // C6. Owner with VIGILANTE_MCP_ALLOW_WRITE=1 still cannot read MCP server PID / PID 1 / host PID
      process.env.VIGILANTE_MCP_TOKEN = ownerRes.secret;
      await assert.rejects(
        client.callTool({
          name: 'scan_process_yara',
          arguments: { pid: process.pid, rule: 'rule Hit { strings: $s = "x" condition: $s }' }
        }),
        /own process/i
      );
      await assert.rejects(
        client.callTool({
          name: 'capture_container_snapshot',
          arguments: { podName: 'p', pid: process.pid }
        }),
        /own process/i
      );
      await assert.rejects(
        client.callTool({
          name: 'capture_container_snapshot',
          arguments: { podName: 'p' }
        }),
        /pid.*required|host PID 1/i
      );

      // Valid mock container PID + rootfsDir (inside VIGILANTE_CONFIG_DIR) works for owner with VIGILANTE_MCP_ALLOW_WRITE=1
      const mockRootfs = path.join(tempRoot, 'cfg', 'mock-rootfs');
      await fs.mkdir(mockRootfs, { recursive: true });
      await fs.writeFile(path.join(mockRootfs, 'dropper.sh'), '#!/bin/sh\necho hi\n');
      const snapOut = path.join(tempRoot, 'cfg', 'snap-out');
      const snapRes = await client.callTool({
        name: 'capture_container_snapshot',
        arguments: { podName: 'web-pod', pid: 99999999, rootfsDir: mockRootfs, outputDir: snapOut }
      });
      const parsedSnap = JSON.parse(snapRes.content[0].text);
      assert.equal(parsedSnap.manifest.podName, 'web-pod');

      // Non-container spawned host child PID is rejected on capture_container_snapshot & scan_process_yara
      const hostChild = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], { stdio: 'ignore' });
      try {
        await new Promise(r => setTimeout(r, 50));
        await assert.rejects(
          client.callTool({
            name: 'capture_container_snapshot',
            arguments: { podName: 'web-pod', pid: hostChild.pid }
          }),
          /non-container or host-sensitive/i
        );
        await assert.rejects(
          client.callTool({
            name: 'scan_process_yara',
            arguments: { pid: hostChild.pid, rule: 'rule Hit { strings: $s = "x" condition: $s }' }
          }),
          /non-container or host-sensitive/i
        );
      } finally {
        hostChild.kill('SIGKILL');
      }

      // investigate_incident schema & handler default automatedContainment to false
      const toolsList = await client.listTools();
      const invTool = toolsList.tools.find(t => t.name === 'investigate_incident');
      assert.match(invTool.inputSchema.properties.automatedContainment.description, /default: false/);
      const invRes = await client.callTool({
        name: 'investigate_incident',
        arguments: {
          target: '198.51.100.200',
          triggerAlert: { severity: 'CRITICAL', title: 'Test Critical Alert', source: 'UnitTest' }
        }
      });
      const parsedInv = JSON.parse(invRes.content[0].text);
      assert.equal(parsedInv.verdict.threatLevel, 'CRITICAL');
      assert.equal(parsedInv.containment, null);
      assert.equal(
        parsedInv.reasoningTrace.some(s => String(s.action || '').startsWith('soar_containment')),
        false
      );
    } finally {
      delete process.env.VIGILANTE_MCP_TOKEN;
      delete process.env.VIGILANTE_MCP_ALLOW_WRITE;
      delete process.env.VIGILANTE_CLI_ADMIN;
      if (prevAuthzFile === undefined) delete process.env.VIGILANTE_AUTHZ_FILE;
      else process.env.VIGILANTE_AUTHZ_FILE = prevAuthzFile;
      invalidateAuthzCache();
      await client.close();
      await server.close();
    }
  });
});
