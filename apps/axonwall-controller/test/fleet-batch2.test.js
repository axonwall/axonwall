import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SATELLITE_HEARTBEAT_MS,
  SATELLITE_LAST_SEEN_GRACE_MS,
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
