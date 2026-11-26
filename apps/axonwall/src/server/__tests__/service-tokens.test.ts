import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { UserSession } from '@axonwall/lib/rbac';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-svc-tokens-'));
const etcDir = path.join(root, 'etc');
const stateDir = path.join(root, 'var');
const persistDir = path.join(stateDir, 'etc-axonwall');
for (const d of [etcDir, stateDir, persistDir]) {
  fs.mkdirSync(d, { recursive: true });
}
process.env.AXONWALL_ETC_DIR = etcDir;
process.env.AXONWALL_STATE_DIR = stateDir;
process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;

import {
  createServiceToken,
  hasServiceTokenScope,
  listServiceTokens,
  revokeServiceToken,
  verifyServiceToken,
} from '../service-tokens';

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('Scoped Service Tokens', () => {
  beforeEach(() => {
    for (const p of [path.join(persistDir, 'service-tokens.json'), path.join(etcDir, 'service-tokens.json')]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  });

  it('creates axw_svc_* tokens, hides secret hash on list, and verifies valid secret', () => {
    const { record, plaintextToken } = createServiceToken({
      name: 'checkpoint1-edge',
      role: 'operator',
      scopes: ['observability:ingest', 'netflow:ingest'],
    });
    expect(plaintextToken).toMatch(/^axw_svc_[a-f0-9]{12}_[a-f0-9]{48}$/);
    expect(record.role).toBe('operator');
    expect(record.scopes).toEqual(['observability:ingest', 'netflow:ingest']);

    const listed = listServiceTokens();
    expect(listed).toHaveLength(1);
    expect((listed[0] as unknown as Record<string, unknown>).secretHash).toBeUndefined();

    const verified = verifyServiceToken(plaintextToken);
    expect(verified).not.toBeNull();
    expect(verified?.id).toBe(record.id);
    expect(verified?.lastUsedAt).toBeTruthy();

    // Tampered secret fails verification
    const tampered = `${plaintextToken.slice(0, -4)}0000`;
    expect(verifyServiceToken(tampered === plaintextToken ? `${plaintextToken.slice(0, -4)}ffff` : tampered)).toBeNull();
    expect(verifyServiceToken('not-a-service-token')).toBeNull();
  });

  it('rejects revoked and expired tokens', () => {
    const { record, plaintextToken } = createServiceToken({
      name: 'ephemeral-edge',
      role: 'readonly',
      scopes: ['observability:ingest'],
    });
    expect(verifyServiceToken(plaintextToken)).not.toBeNull();

    expect(revokeServiceToken(record.id)).toBe(true);
    expect(revokeServiceToken('nonexistent-id')).toBe(false);
    expect(verifyServiceToken(plaintextToken)).toBeNull();

    // Simulate expired token on disk
    const { record: rec2, plaintextToken: tok2 } = createServiceToken({
      name: 'expired-edge',
      role: 'operator',
      scopes: ['observability:ingest'],
    });
    const p = path.join(persistDir, 'service-tokens.json');
    const raw = JSON.parse(fs.readFileSync(p, 'utf-8')) as Array<Record<string, unknown>>;
    const updated = raw.map((item) =>
      item.id === rec2.id ? { ...item, expiresAt: new Date(Date.now() - 60_000).toISOString() } : item
    );
    fs.writeFileSync(p, JSON.stringify(updated, null, 2));
    fs.writeFileSync(path.join(etcDir, 'service-tokens.json'), JSON.stringify(updated, null, 2));
    expect(verifyServiceToken(tok2)).toBeNull();
  });

  it('enforces scopes only on service_token sessions and honors wildcard', () => {
    const interactive: UserSession = {
      userId: 'u1',
      username: 'admin',
      source: 'local_admin',
      roles: ['admin'],
      privileges: ['*'],
      exp: 9999999999,
    };
    expect(hasServiceTokenScope(interactive, 'observability:mitigate')).toBe(true);
    expect(hasServiceTokenScope(null, 'observability:ingest')).toBe(false);

    const limited: UserSession = {
      userId: 'svc:abc',
      username: 'svc:edge1',
      source: 'service_token',
      roles: ['operator'],
      privileges: [],
      exp: 9999999999,
      tokenId: 'abc',
      scopes: ['observability:ingest'],
    };
    expect(hasServiceTokenScope(limited, 'observability:ingest')).toBe(true);
    expect(hasServiceTokenScope(limited, 'observability:mitigate')).toBe(false);

    const wildcard: UserSession = { ...limited, scopes: ['*'] };
    expect(hasServiceTokenScope(wildcard, 'observability:mitigate')).toBe(true);
  });
});
