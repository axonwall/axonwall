import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import {
  ensureControllerTls,
  validateHaTransition,
  isValidMacAddress,
  isValidCidr,
  shouldPruneDisconnectedSatellite,
  MESH_DISCONNECTED_GRACE_MS,
  headscaleRetryDelaysMs,
  provisionHeadscaleWithRetry,
} from '../dist/index.js';

// Regression tests for Batch 2 of the 2026-11-04 Axonwall bug hunt:
// B-H2a, B-H2b, B-M6 (HA endpoint), B-M2 (mesh pruning), B-H4
// (Headscale retry), B-H3 (controller TLS operator-CA refusal).
// The HA endpoint handler itself lives inside main() and is not
// exported, so these tests cover the exported validation/provisioning
// helpers the handler is built on; the handler wires them verbatim
// (unknown role -> 400, PROMOTE without satelliteId -> 400, named
// target with no connected satellite -> 404, demote-before-promote).

test('B-H2a: unknown, missing and typo roles are rejected, never defaulted to DEMOTE', () => {
  for (const payload of [{}, { role: '' }, { role: 'primary' }, { role: 'activ' }, { role: 'leader' }, { role: 'master2' }]) {
    const v = validateHaTransition(payload);
    assert.equal(v.ok, false, `payload ${JSON.stringify(payload)} must not validate`);
    assert.equal(v.status, 400);
    assert.match(v.error, /role/i);
  }
  // Known roles still validate (DEMOTE needs no target; PROMOTE does).
  assert.equal(validateHaTransition({ role: 'standby' }).ok, true);
  assert.equal(validateHaTransition({ role: 'standby' }).transition, 'DEMOTE');
  assert.equal(validateHaTransition({ role: 'demote' }).transition, 'DEMOTE');
  assert.equal(validateHaTransition({ role: 'backup' }).transition, 'DEMOTE');
  assert.equal(validateHaTransition({ role: 'master', satelliteId: 'edge-a', lanVip: '10.0.0.1/24' }).transition, 'PROMOTE');
  assert.equal(validateHaTransition({ role: 'ACTIVE', satelliteId: 'edge-a', lanVip: '10.0.0.1/24' }).transition, 'PROMOTE');
  // Legacy `type: PROMOTE` alias still works when no role is given.
  assert.equal(validateHaTransition({ type: 'PROMOTE', satelliteId: 'edge-a', lanVip: '10.0.0.1/24' }).transition, 'PROMOTE');
});

test('B-H2b: PROMOTE without an explicit satelliteId is rejected', () => {
  const v = validateHaTransition({ role: 'active', lanVip: '10.0.0.1/24' });
  assert.equal(v.ok, false);
  assert.equal(v.status, 400);
  assert.match(v.error, /satelliteId is required for PROMOTE/);
  const blank = validateHaTransition({ role: 'active', satelliteId: '   ', lanVip: '10.0.0.1/24' });
  assert.equal(blank.ok, false);
});

test('B-M6: sharedWanMac must be a MAC, lanVip must be a CIDR, no hardcoded VIP default', () => {
  assert.equal(isValidMacAddress('02:00:00:00:00:01'), true);
  assert.equal(isValidMacAddress('02-00-00-00-00-01'), true);
  assert.equal(isValidMacAddress('not-a-mac'), false);
  assert.equal(isValidMacAddress('02:00:00:00:00:01/24'), false);
  assert.equal(isValidCidr('10.0.0.1/24'), true);
  assert.equal(isValidCidr('fd00::1/64'), true);
  assert.equal(isValidCidr('10.0.0.1'), false);
  assert.equal(isValidCidr('10.0.0.1/33'), false);
  assert.equal(isValidCidr('999.0.0.1/24'), false);

  const badMac = validateHaTransition({ role: 'active', satelliteId: 'edge-a', sharedWanMac: 'zz:00:00:00:00:01', lanVip: '10.0.0.1/24' });
  assert.equal(badMac.ok, false);
  assert.match(badMac.error, /sharedWanMac/);

  // A hyphenated MAC is accepted and normalized to lowercase colons.
  const hyphen = validateHaTransition({ role: 'active', satelliteId: 'edge-a', sharedWanMac: '02-00-00-00-00-01', lanVip: '10.0.0.1/24' });
  assert.equal(hyphen.ok, true);
  assert.equal(hyphen.sharedWanMac, '02:00:00:00:00:01');

  const badVip = validateHaTransition({ role: 'active', satelliteId: 'edge-a', lanVip: '10.0.0.1' });
  assert.equal(badVip.ok, false);
  assert.match(badVip.error, /lanVip/);

  // No lanVip and no fleet LAN address: rejected, NOT silently
  // substituted with 10.0.0.1/24 (the old default).
  const missing = validateHaTransition({ role: 'active', satelliteId: 'edge-a' });
  assert.equal(missing.ok, false);
  assert.match(missing.error, /lanVip is required/);

  // Fleet config is the only permitted non-explicit VIP source.
  const fromFleet = validateHaTransition({ role: 'active', satelliteId: 'edge-a' }, '192.168.7.1/24');
  assert.equal(fromFleet.ok, true);
  assert.equal(fromFleet.lanVip, '192.168.7.1/24');

  // An invalid fleet VIP does not rescue a missing explicit VIP.
  const badFleet = validateHaTransition({ role: 'active', satelliteId: 'edge-a' }, 'not-a-cidr');
  assert.equal(badFleet.ok, false);
});

test('B-M2: disconnected satellites prune only after the grace period', () => {
  const now = Date.now();
  assert.equal(shouldPruneDisconnectedSatellite(undefined, now), false);
  assert.equal(shouldPruneDisconnectedSatellite(new Date(now - 60 * 1000).toISOString(), now), false);
  assert.equal(shouldPruneDisconnectedSatellite(new Date(now - MESH_DISCONNECTED_GRACE_MS - 1000).toISOString(), now), true);
  assert.equal(shouldPruneDisconnectedSatellite(new Date(now - MESH_DISCONNECTED_GRACE_MS).toISOString(), now), true);
  assert.equal(shouldPruneDisconnectedSatellite('not-a-date', now), false);
  // A short explicit grace still gates pruning.
  assert.equal(shouldPruneDisconnectedSatellite(new Date(now - 5000).toISOString(), now, 60 * 1000), false);
  assert.equal(shouldPruneDisconnectedSatellite(new Date(now - 61000).toISOString(), now, 60 * 1000), true);
});

test('B-H4: Headscale provisioning retries on bounded backoff until the key is sent', async () => {
  const delays = headscaleRetryDelaysMs();
  assert.deepEqual(delays[0], 0);
  assert.ok(delays.length >= 2, 'at least one retry must be scheduled');
  assert.ok(delays.every((d) => Number.isInteger(d) && d >= 0), 'delays are non-negative integers');

  let attempts = 0;
  const slept = [];
  const sent = [];
  const ok = await provisionHeadscaleWithRetry({
    listUsers: async () => [],
    createUser: async () => ({ name: 'satellites' }),
    createPreAuthKey: async () => {
      attempts++;
      if (attempts < 3) throw new Error('headscale down');
      return { key: 'test-key-3rd-try' };
    },
    serverUrl: 'https://hub.axonwall.local',
    send: (msg) => sent.push(msg),
    isOpen: () => true,
    sleep: async (ms) => { slept.push(ms); },
  });
  assert.equal(ok, true);
  assert.equal(attempts, 3, 'provisioning must retry past transient failures');
  assert.deepEqual(slept, delays.slice(1, 3), 'retries wait the scheduled backoff between attempts');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, 'SYNC_HEADSCALE');
  assert.equal(sent[0].payload.authKey, 'test-key-3rd-try');
});

test('B-H4: Headscale provisioning stops retrying when the socket closes, and gives up after the bounded attempts', async () => {
  // Socket closes after the first failure: no further attempts.
  // (Attempts are counted at listUsers, the first step of an attempt.)
  let attempts = 0;
  let open = true;
  const okClosed = await provisionHeadscaleWithRetry({
    listUsers: async () => { attempts++; throw new Error('headscale down'); },
    createUser: async () => { throw new Error('unreachable'); },
    createPreAuthKey: async () => { throw new Error('headscale down'); },
    serverUrl: 'https://hub.axonwall.local',
    send: () => { throw new Error('send must not happen'); },
    isOpen: () => open,
    sleep: async () => { open = false; },
  });
  assert.equal(okClosed, false);
  assert.equal(attempts, 1, 'a closed socket must stop the retry loop');

  // Socket stays open but Headscale never recovers: attempts are bounded.
  let boundedAttempts = 0;
  const okBounded = await provisionHeadscaleWithRetry({
    listUsers: async () => { boundedAttempts++; throw new Error('headscale down'); },
    createUser: async () => { throw new Error('unreachable'); },
    createPreAuthKey: async () => { throw new Error('headscale down'); },
    serverUrl: 'https://hub.axonwall.local',
    send: () => { throw new Error('send must not happen'); },
    isOpen: () => true,
    sleep: async () => {},
  });
  assert.equal(okBounded, false);
  assert.equal(boundedAttempts, headscaleRetryDelaysMs().length, 'attempts must equal the bounded schedule, no more');
});

test('B-H3: operator-CA mode refuses to mint a self-signed hub leaf and fails loudly', (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axon_tls_bh3_'));
  const certPath = path.join(tmpDir, 'hub.crt');
  const keyPath = path.join(tmpDir, 'hub.key');
  const caPath = path.join(tmpDir, 'ca.crt');
  const caKeyPath = path.join(tmpDir, 'ca.key');
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  // Build a real operator CA (key kept OUT of this directory to model
  // operator-CA mode: ca.crt present, ca.key absent).
  const caDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axon_tls_bh3_ca_'));
  t.after(() => fs.rmSync(caDir, { recursive: true, force: true }));
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${path.join(caDir, 'ca.key')} -out ${caPath} -days 3650 -nodes -subj "/CN=test-operator-ca"`, { stdio: 'ignore' });
  assert.equal(fs.existsSync(caPath), true);
  assert.equal(fs.existsSync(caKeyPath), false, 'fixture must model operator-CA mode (no on-box CA key)');

  assert.throws(
    () => ensureControllerTls(certPath, keyPath, caPath, caKeyPath),
    /Refusing to mint a self-signed hub certificate/,
    'operator-CA mode must throw instead of minting a non-chaining leaf',
  );
  assert.equal(fs.existsSync(certPath), false, 'no self-signed leaf may be written in operator-CA mode');
  assert.equal(fs.existsSync(keyPath), false);
});

test('B-H3: an existing leaf that does not chain to the on-disk CA is ignored, not served', (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axon_tls_bh3_chain_'));
  const certPath = path.join(tmpDir, 'hub.crt');
  const keyPath = path.join(tmpDir, 'hub.key');
  const caPath = path.join(tmpDir, 'ca.crt');
  const caKeyPath = path.join(tmpDir, 'ca.key');
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  // Appliance-CA mode (key present) so the refusal does not fire, but
  // the leaf is self-signed and does NOT chain to the CA: it must not
  // be returned as the served certificate.
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${caKeyPath} -out ${caPath} -days 3650 -nodes -subj "/CN=test-ca"`, { stdio: 'ignore' });
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} -days 3650 -nodes -subj "/CN=axonwall"`, { stdio: 'ignore' });
  const before = fs.readFileSync(certPath);
  const tlsConfig = ensureControllerTls(certPath, keyPath, caPath, caKeyPath);
  assert.ok(tlsConfig, 'a replacement certificate must be provisioned');
  assert.ok(!tlsConfig.cert.equals(before), 'the non-chaining leaf must not be served as-is');
  assert.ok(tlsConfig.ca, 'the on-disk CA must be included in the returned config');
});
