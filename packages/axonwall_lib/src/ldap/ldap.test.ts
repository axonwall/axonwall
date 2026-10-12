import { describe, it, expect } from 'vitest';
import * as crypto from 'node:crypto';
import { authenticateLocalAdmin, escapeLdapFilter } from './index.js';

describe('escapeLdapFilter', () => {
  it('escapes RFC 4515 special characters (*, (, ), \\, NUL)', () => {
    expect(escapeLdapFilter('admin*')).toBe('admin\\2a');
    expect(escapeLdapFilter('(admin)')).toBe('\\28admin\\29');
    expect(escapeLdapFilter('admin\\user')).toBe('admin\\5cuser');
    expect(escapeLdapFilter('admin\x00root')).toBe('admin\\00root');
  });

  it('leaves standard characters unescaped', () => {
    expect(escapeLdapFilter('normal_user-123.test@domain')).toBe('normal_user-123.test@domain');
    expect(escapeLdapFilter('NUL')).toBe('NUL'); // Does not escape 'N', 'U', 'L'
  });
});

describe('authenticateLocalAdmin', () => {
  it('authenticates valid plaintext password with timingSafeEqual', () => {
    const res = authenticateLocalAdmin('admin', 'secret123', 'admin', 'secret123');
    expect(res.success).toBe(true);
    expect(res.session?.username).toBe('admin');
    expect(res.session?.roles).toContain('admin');
  });

  it('rejects incorrect password', () => {
    const res = authenticateLocalAdmin('admin', 'wrongpass', 'admin', 'secret123');
    expect(res.success).toBe(false);
    expect(res.error).toBe('Invalid local administrator credentials');
  });

  it('rejects incorrect username', () => {
    const res = authenticateLocalAdmin('notadmin', 'secret123', 'admin', 'secret123');
    expect(res.success).toBe(false);
  });

  it('authenticates with scrypt hashed password', () => {
    const salt = 'randomsalt123456';
    const hash = crypto.scryptSync('mycomplexpass', salt, 64).toString('hex');
    const stored = `scrypt$${salt}$${hash}`;

    const validRes = authenticateLocalAdmin('admin', 'mycomplexpass', 'admin', stored);
    expect(validRes.success).toBe(true);
    expect(validRes.session?.userId).toBe('local-admin-root');

    const invalidRes = authenticateLocalAdmin('admin', 'badpass', 'admin', stored);
    expect(invalidRes.success).toBe(false);
  });

  it('rejects empty credentials safely without throwing', () => {
    expect(authenticateLocalAdmin('', '', 'admin', 'pass').success).toBe(false);
    expect(authenticateLocalAdmin('admin', '', 'admin', 'pass').success).toBe(false);
    expect(authenticateLocalAdmin('admin', 'pass', '', '').success).toBe(false);
  });
});
