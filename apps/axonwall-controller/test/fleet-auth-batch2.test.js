import test from 'node:test';
import assert from 'node:assert/strict';
import { secureTokenEquals } from '../dist/index.js';

// Regression tests for Batch 2 of the 2026-11-05 round-2 Axonwall
// bug hunt: B2-H1. Both fleet-auth call sites (verifyFleetAuth and
// the /ws/satellite upgrade handler) compared token lengths with
// `String.length` (UTF-16 code units) and then called
// `crypto.timingSafeEqual` on the UTF-8 buffers with no try/catch.
// A wrong token with the same UTF-16 length but a different byte
// length (one multibyte character) threw
// ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH as an uncaught exception and
// killed the controller process. The comparison must be a plain
// false for any wrong token, whatever its byte length.

test('B2-H1: multibyte token with the same UTF-16 length is false, never a throw', () => {
  const expected = 'a'.repeat(30);
  // 29 ASCII + 'é': 30 UTF-16 code units, 31 UTF-8 bytes.
  const attacker = 'a'.repeat(29) + 'é';
  assert.equal(attacker.length, expected.length, 'fixture must have equal UTF-16 lengths');
  assert.notEqual(Buffer.from(attacker).length, Buffer.from(expected).length, 'fixture must have unequal byte lengths');
  assert.equal(secureTokenEquals(attacker, expected), false);
});

test('B2-H1: exact token matches, including a multibyte expected token', () => {
  assert.equal(secureTokenEquals('a'.repeat(30), 'a'.repeat(30)), true);
  const expected = 'é'.repeat(10);
  assert.equal(secureTokenEquals('é'.repeat(10), expected), true);
  // Same UTF-16 length, different multibyte content: false, no throw.
  assert.equal(secureTokenEquals('ü'.repeat(10), expected), false);
});

test('B2-H1: wrong ASCII token, missing and non-string tokens are false', () => {
  assert.equal(secureTokenEquals('b'.repeat(30), 'a'.repeat(30)), false);
  assert.equal(secureTokenEquals('short', 'a'.repeat(30)), false);
  assert.equal(secureTokenEquals('', 'a'.repeat(30)), false);
  assert.equal(secureTokenEquals(undefined, 'a'.repeat(30)), false);
  assert.equal(secureTokenEquals(null, 'a'.repeat(30)), false);
  assert.equal(secureTokenEquals(12345, 'a'.repeat(30)), false);
});
