import { describe, it, expect } from 'vitest';
import { ZeroTrustAppSchema } from './index.js';

// Audit B-S3: the zero-trust app role model must fail closed at the
// schema level — no phantom roles in the default, open access only as
// the explicit allowAnyAuthenticated flag, and an explicitly emptied
// role list preserved as-is so the gateway authorizer can apply its
// admin-only treatment to it.
describe('ZeroTrustAppSchema role model (B-S3)', () => {
  const base = {
    name: 'Grafana',
    publicHostname: 'grafana.example.com',
    internalUpstream: 'http://10.0.0.5:3000',
  };

  it('defaults allowedRoles to admin only, with no phantom roles', () => {
    const app = ZeroTrustAppSchema.parse(base);
    expect(app.allowedRoles).toEqual(['admin']);
    expect(app.allowedRoles).not.toContain('user');
  });

  it('defaults allowAnyAuthenticated to false', () => {
    const app = ZeroTrustAppSchema.parse(base);
    expect(app.allowAnyAuthenticated).toBe(false);
  });

  it('preserves an explicitly emptied role list instead of refilling it', () => {
    const app = ZeroTrustAppSchema.parse({ ...base, allowedRoles: [] });
    expect(app.allowedRoles).toEqual([]);
    expect(app.allowAnyAuthenticated).toBe(false);
  });

  it('keeps an explicit open-access choice and role list intact', () => {
    const open = ZeroTrustAppSchema.parse({ ...base, allowAnyAuthenticated: true });
    expect(open.allowAnyAuthenticated).toBe(true);
    const roled = ZeroTrustAppSchema.parse({ ...base, allowedRoles: ['operator', 'readonly'] });
    expect(roled.allowedRoles).toEqual(['operator', 'readonly']);
  });
});
