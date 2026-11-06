import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  SATELLITE_HEARTBEAT_MS,
  SATELLITE_LAST_SEEN_GRACE_MS,
  loadPersistedHaState,
  persistHaState,
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
