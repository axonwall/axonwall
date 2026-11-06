// B2-M7 follow-up: the per-satellite synced-routes record is now
// persisted to disk (same pattern as the B-H2b persisted HA
// state), so a controller restart no longer loses it. These tests
// pin the round-trip, the corrupt-file tolerance, and the restart
// scenario itself: a route deleted from DesiredState while the
// controller was down must still be deleted on the first sync
// after the restart, because the record survives in the file.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-synced-routes-followup-'));
const routesPath = path.join(tmpDir, 'synced-routes.json');
process.env.AXONWALL_SYNCED_ROUTES_PATH = routesPath;

const { loadPersistedSyncedRoutes, persistSyncedRoutes, computeRoutesToDelete } = await import('../dist/index.js');

const routeA = { destination: '10.1.0.0/24', gateway: '192.168.1.1', device: 'eth0' };
const routeB = { destination: '10.2.0.0/24', gateway: '192.168.1.1', device: 'eth0' };
const routeC = { destination: '10.3.0.0/24', gateway: '192.168.1.2' };

test.after(() => {
  delete process.env.AXONWALL_SYNCED_ROUTES_PATH;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('B2-M7 follow-up: synced-routes state round-trips through disk', (t) => {
  t.after(() => { try { fs.unlinkSync(routesPath); } catch {} });
  assert.equal(loadPersistedSyncedRoutes(), null, 'no record before any sync');
  persistSyncedRoutes({ 'edge-1': [routeA, routeB], 'edge-2': [routeC] });
  assert.deepEqual(loadPersistedSyncedRoutes(), { 'edge-1': [routeA, routeB], 'edge-2': [routeC] });
  // Overwriting one satellite keeps the other intact.
  persistSyncedRoutes({ 'edge-1': [routeA], 'edge-2': [routeC] });
  assert.deepEqual(loadPersistedSyncedRoutes(), { 'edge-1': [routeA], 'edge-2': [routeC] });
  // An empty list is a real record (all routes deleted), not "no record".
  persistSyncedRoutes({ 'edge-1': [], 'edge-2': [routeC] });
  assert.deepEqual(loadPersistedSyncedRoutes(), { 'edge-1': [], 'edge-2': [routeC] });
});

test('B2-M7 follow-up: corrupt or malformed synced-routes state is ignored, not fatal', (t) => {
  t.after(() => { try { fs.unlinkSync(routesPath); } catch {} });
  fs.writeFileSync(routesPath, '{not json');
  assert.equal(loadPersistedSyncedRoutes(), null, 'unparseable state must be ignored');
  fs.writeFileSync(routesPath, JSON.stringify(['not', 'a', 'map']));
  assert.equal(loadPersistedSyncedRoutes(), null, 'a top-level array must be ignored');
  fs.writeFileSync(routesPath, JSON.stringify({
    'edge-1': [routeA, { gateway: '192.168.1.1' }, 'junk', { destination: '10.9.0.0/24', gateway: '192.168.1.1', device: 7 }],
    'edge-2': 'not-an-array',
  }));
  assert.deepEqual(
    loadPersistedSyncedRoutes(),
    { 'edge-1': [routeA] },
    'malformed route entries must be dropped and valid ones kept; a non-array value leaves no record for that satellite',
  );
});

test('B2-M7 follow-up: a route deleted while the controller was down is still deleted after restart', (t) => {
  t.after(() => { try { fs.unlinkSync(routesPath); } catch {} });
  // Before the "restart": the controller pushed routes A and B to edge-1.
  persistSyncedRoutes({ 'edge-1': [routeA, routeB] });

  // The "restart": a fresh load from disk, as a new process does
  // at startup, with no in-memory record at all.
  const reloaded = loadPersistedSyncedRoutes();
  assert.deepEqual(reloaded, { 'edge-1': [routeA, routeB] });

  // While the controller was down the operator deleted route B
  // from DesiredState; the first sync after restart pushes only A.
  const routesToDelete = computeRoutesToDelete(reloaded['edge-1'] ?? [], [routeA]);
  assert.deepEqual(routesToDelete, [routeB], 'the restart must not lose the deletion');
});

test('B2-M7 follow-up: no record means no deletions, as before', () => {
  assert.deepEqual(computeRoutesToDelete([], [routeA]), []);
});
