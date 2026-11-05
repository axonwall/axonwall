import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFleetSyncBody } from '../dist/index.js';

// Regression tests for Batch 7 of the 2026-11-04 Axonwall bug hunt:
// B-H1 (/fleet/sync treating an invalid/empty body as "sync with
// empty state" and pushing default edge config).
//
// The handler wires parseFleetSyncBody verbatim: a 400 here means no
// satellite was synced, and `desired: undefined` means "load the
// on-disk state" (syncSatelliteDesiredState loads
// /etc/axonwall/state.json only when the argument is undefined;
// null used to mean "sync with empty state").

test('B-H1: empty body means re-sync from disk (desired undefined), not empty state', () => {
  for (const body of ['', '   ', '\n\t']) {
    const v = parseFleetSyncBody(body);
    assert.equal(v.ok, true, `body ${JSON.stringify(body)} must validate`);
    assert.equal(v.desired, undefined, 'empty body must yield desired === undefined so disk state loads');
  }
});

test('B-H1: non-empty body failing schema validation is a 400, never a sync', () => {
  for (const body of [
    '{"version": "not-a-number"}',
    '{"interfaces": "not-an-array"}',
    '{"rules": [{"action": "bogus-action"}]}',
    '[1, 2, 3]',
    '"just a string"',
  ]) {
    const v = parseFleetSyncBody(body);
    assert.equal(v.ok, false, `body ${body} must not validate`);
    assert.equal(v.status, 400);
    assert.match(v.error, /Invalid DesiredState/i);
  }
});

test('B-H1: malformed JSON is a 400', () => {
  const v = parseFleetSyncBody('{not json');
  assert.equal(v.ok, false);
  assert.equal(v.status, 400);
  assert.match(v.error, /Invalid JSON/i);
});

test('B-H1: a valid DesiredState body parses through', () => {
  const v = parseFleetSyncBody('{}');
  assert.equal(v.ok, true);
  assert.notEqual(v.desired, undefined);
  assert.equal(v.desired.version, 1);
  const v2 = parseFleetSyncBody('{"version": 3, "interfaces": []}');
  assert.equal(v2.ok, true);
  assert.equal(v2.desired.version, 3);
});
