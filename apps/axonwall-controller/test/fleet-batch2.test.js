import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  SATELLITE_HEARTBEAT_MS,
  SATELLITE_LAST_SEEN_GRACE_MS,
  PENDING_COMMAND_STALE_MS,
  HEADSCALE_RECHECK_MS,
  headscaleRetryDelaysMs,
  buildSatelliteCommandEnvelope,
  isPendingCommandStale,
  recordCommandAck,
  loadPersistedHaState,
  persistHaState,
  computeRoutesToDelete,
  shouldRefuseFleetSync,
} from '../dist/index.js';

// Regression tests for Batch 2 of the 2026-11-05 round-2 Axonwall
// bug hunt: B2-H2 (no liveness detection for half-open satellite
// sockets). The heartbeat itself runs inside main() and is covered
// by the timer wiring; these pin the timing relationship the fix
// depends on: a live satellite (15 s telemetry cadence) must never
// be killed for one slow interval, and a dead socket must be
// terminated long before the 24 h prune timer would ever see it.

test('B2-H2: lastSeen grace is far above the heartbeat interval and the telemetry cadence', () => {
  const telemetryCadenceMs = 15 * 1000;
  assert.ok(SATELLITE_HEARTBEAT_MS > 0, 'heartbeat interval must be positive');
  assert.ok(
    SATELLITE_LAST_SEEN_GRACE_MS >= 5 * SATELLITE_HEARTBEAT_MS,
    'grace must cover several missed heartbeats so one slow pong cannot kill a live socket',
  );
  assert.ok(
    SATELLITE_LAST_SEEN_GRACE_MS >= 10 * telemetryCadenceMs,
    'grace must be far above the 15 s telemetry cadence',
  );
  assert.ok(
    SATELLITE_LAST_SEEN_GRACE_MS < 24 * 60 * 60 * 1000,
    'grace must be far below the 24 h disconnected-entry prune',
  );
});

// B-H2b residual: the active edge must survive a controller
// restart (and an active-edge flap, which the close handler used
// to turn into a forgotten active edge). The record is a plain
// JSON file; the handler persists it on every change and loads it
// at startup, and only an explicit DEMOTE clears it.

test('B-H2b residual: persisted HA state round-trips, and a clear persists as null', (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-ha-state-'));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));
  process.env.AXONWALL_HA_STATE_PATH = path.join(tmpDir, 'active-ha-edge.json');
  t.after(() => { delete process.env.AXONWALL_HA_STATE_PATH; });

  assert.equal(loadPersistedHaState(), null, 'no record before any promotion');

  persistHaState({ activeHaEdgeId: 'edge-a', sharedWanMac: '02:00:00:00:00:01', lanVip: '10.0.0.1/24' });
  assert.deepEqual(loadPersistedHaState(), {
    activeHaEdgeId: 'edge-a',
    sharedWanMac: '02:00:00:00:00:01',
    lanVip: '10.0.0.1/24',
  });

  persistHaState({ activeHaEdgeId: null });
  assert.deepEqual(loadPersistedHaState(), { activeHaEdgeId: null });
});

test('B-H2b residual: corrupt persisted HA state is ignored, not fatal', (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-ha-state-'));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));
  const statePath = path.join(tmpDir, 'active-ha-edge.json');
  process.env.AXONWALL_HA_STATE_PATH = statePath;
  t.after(() => { delete process.env.AXONWALL_HA_STATE_PATH; });

  fs.writeFileSync(statePath, '{not json');
  assert.equal(loadPersistedHaState(), null);
  fs.writeFileSync(statePath, JSON.stringify({ activeHaEdgeId: 42 }));
  assert.equal(loadPersistedHaState(), null);
});

// B2-M1: the controller ignored satellite COMMAND_ACKs, so
// sync/HA/block reported success on ws.send alone while the
// satellite may have failed the apply. Every outbound command now
// carries a commandId the satellite echoes in its ack, failures
// are recorded per satellite, and acks that never arrive are
// swept instead of leaking.

test('B2-M1: outbound envelope carries the commandId the satellite echoes', () => {
  const raw = buildSatelliteCommandEnvelope('SYNC_ROUTES', { routes: [] }, 'cmd_abc123');
  const env = JSON.parse(raw);
  assert.equal(env.type, 'SYNC_ROUTES');
  assert.equal(env.commandId, 'cmd_abc123');
  assert.deepEqual(env.payload, { routes: [] });
});

test('B2-M1: a failed ack records the last apply error; a later success clears it', () => {
  const state = {};
  recordCommandAck(state, { command: 'SYNC_INTERFACES', success: false, error: 'device eth1 missing' });
  assert.equal(state.lastApplyError, 'SYNC_INTERFACES: device eth1 missing');

  // Success of a different command leaves the failure recorded.
  recordCommandAck(state, { command: 'PROMOTE', success: true });
  assert.equal(state.lastApplyError, 'SYNC_INTERFACES: device eth1 missing');

  // Success of the same command clears it.
  recordCommandAck(state, { command: 'SYNC_INTERFACES', success: true });
  assert.equal(state.lastApplyError, undefined);
});

test('B2-M1: pending commands go stale after the grace period, not before', () => {
  const sentAt = 1_000_000;
  assert.equal(isPendingCommandStale(sentAt, sentAt + PENDING_COMMAND_STALE_MS), false);
  assert.equal(isPendingCommandStale(sentAt, sentAt + PENDING_COMMAND_STALE_MS + 1), true);
});

// B-H4 residual: the bounded Headscale backoff exhausts after
// ~110 s and then nothing retried on a socket that stayed open
// after Headscale recovered. The slow re-check must be far above
// one backoff run so a recovering Headscale is not hammered, and
// the satellite-side half (telemetry headscaleEnrolled) is what
// lets the hub distrust its latched flag for a wiped satellite.

test('B-H4 residual: slow Headscale re-check is far above one bounded backoff run', () => {
  const backoffTotalMs = headscaleRetryDelaysMs().reduce((a, b) => a + b, 0);
  assert.ok(backoffTotalMs > 0, 'backoff schedule must be non-empty');
  assert.ok(
    HEADSCALE_RECHECK_MS >= 2 * backoffTotalMs,
    `re-check (${HEADSCALE_RECHECK_MS}ms) must be far above one backoff run (${backoffTotalMs}ms)`,
  );
});

test('B2-M7: routes removed from the enabled set are computed as deletions', () => {
  const previous = [
    { destination: '10.1.0.0/24', gateway: '10.0.0.254', device: 'eth0' },
    { destination: '10.2.0.0/24', gateway: '10.0.0.254', device: 'eth0' },
    { destination: 'default', gateway: '10.0.0.1' },
  ];
  const current = [
    { destination: '10.1.0.0/24', gateway: '10.0.0.254', device: 'eth0' },
    { destination: 'default', gateway: '10.0.0.1' },
  ];
  assert.deepEqual(computeRoutesToDelete(previous, current), [
    { destination: '10.2.0.0/24', gateway: '10.0.0.254', device: 'eth0' },
  ]);
});

test('B2-M7: a first sync has no deletions, and device distinguishes routes', () => {
  assert.deepEqual(computeRoutesToDelete([], [{ destination: '10.1.0.0/24', gateway: '10.0.0.254' }]), []);
  // Same destination + gateway on a different device is a
  // different route: the old device binding must be deleted.
  assert.deepEqual(
    computeRoutesToDelete(
      [{ destination: '10.1.0.0/24', gateway: '10.0.0.254', device: 'eth0' }],
      [{ destination: '10.1.0.0/24', gateway: '10.0.0.254', device: 'eth1' }],
    ),
    [{ destination: '10.1.0.0/24', gateway: '10.0.0.254', device: 'eth0' }],
  );
  // Identical sets delete nothing.
  const routes = [{ destination: '10.1.0.0/24', gateway: '10.0.0.254', device: 'eth0' }];
  assert.deepEqual(computeRoutesToDelete(routes, routes), []);
});

test('B2-M8: /fleet/sync refuses only when no DesiredState exists anywhere', () => {
  // Empty body + no disk state: refuse (fail closed, no defaults).
  assert.equal(shouldRefuseFleetSync(undefined, null), true);
  // A supplied body proceeds even with no disk state.
  assert.equal(shouldRefuseFleetSync({ interfaces: [] }, null), false);
  // An empty body proceeds when disk state exists.
  assert.equal(shouldRefuseFleetSync(undefined, { interfaces: [] }), false);
  // Both present proceeds.
  assert.equal(shouldRefuseFleetSync({ interfaces: [] }, { interfaces: [] }), false);
});
