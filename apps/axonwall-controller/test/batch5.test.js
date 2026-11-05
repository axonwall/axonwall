import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveSatelliteRole } from '../dist/index.js';

// Regression tests for Batch 5 of the 2026-11-04 Axonwall bug hunt:
// B-M5 (edge role latched, never reconciled). The telemetry handler
// and syncSatelliteDesiredState both derive the role through this
// helper, so these cases pin the shared rule: a configured fleet
// role always wins, telemetry/id-prefix are fallbacks for
// unconfigured nodes only, and a telemetry-latched edge role clears
// when pid1Mode stops being reported.

test('B-M5: configured role wins over telemetry and id-prefix', () => {
  // Configured satellite clears a latched edge role even though the
  // node transiently reported pid1Mode.
  assert.equal(
    deriveSatelliteRole({ configuredRole: 'satellite', currentRole: 'edge-ngfw', satelliteId: 'sat-1', pid1ModeReported: true }),
    'satellite',
  );
  // Configured edge wins even when telemetry says nothing.
  assert.equal(
    deriveSatelliteRole({ configuredRole: 'edge-ngfw', currentRole: 'satellite', satelliteId: 'sat-1', pid1ModeReported: false }),
    'edge-ngfw',
  );
  // Configured role wins on the sync path too.
  assert.equal(
    deriveSatelliteRole({ configuredRole: 'satellite', currentRole: 'edge-ngfw', satelliteId: 'edge-9' }),
    'satellite',
  );
});

test('B-M5: telemetry pid1Mode latches edge for unconfigured nodes', () => {
  assert.equal(
    deriveSatelliteRole({ currentRole: 'satellite', satelliteId: 'sat-1', pid1ModeReported: true }),
    'edge-ngfw',
  );
});

test('B-M5: pid1Mode stopping clears a telemetry-latched edge role, not an id-prefix one', () => {
  // Plain id + previously latched edge + no pid1Mode now => cleared.
  assert.equal(
    deriveSatelliteRole({ currentRole: 'edge-ngfw', satelliteId: 'sat-1', pid1ModeReported: false }),
    'satellite',
  );
  // Edge-like id keeps the edge role: the id-prefix fallback still
  // justifies it independently of telemetry.
  assert.equal(
    deriveSatelliteRole({ currentRole: 'edge-ngfw', satelliteId: 'edge-9', pid1ModeReported: false }),
    'edge-ngfw',
  );
  assert.equal(
    deriveSatelliteRole({ currentRole: 'edge-ngfw', satelliteId: 'edge', pid1ModeReported: false }),
    'edge-ngfw',
  );
});

test('B-M5: sync path keeps latched edge or id-prefix fallback for unconfigured nodes', () => {
  assert.equal(
    deriveSatelliteRole({ currentRole: 'edge-ngfw', satelliteId: 'sat-1' }),
    'edge-ngfw',
  );
  assert.equal(
    deriveSatelliteRole({ currentRole: undefined, satelliteId: 'edge-9' }),
    'edge-ngfw',
  );
  assert.equal(
    deriveSatelliteRole({ currentRole: undefined, satelliteId: 'sat-1' }),
    'satellite',
  );
  assert.equal(
    deriveSatelliteRole({ currentRole: 'satellite', satelliteId: 'sat-1' }),
    'satellite',
  );
});
