// Test helper (not a test file): authenticates one MCP token N
// times in a FRESH process, printing ALLOWED / DENIED per attempt.
// Used by round4-batch2.test.js to prove the per-key rate-limit
// budget survives across stdio process invocations (R4-B-L2).
// Env: AXONWALL_MCP_KEYS_PATH, AXONWALL_MCP_RATE_LIMIT_PATH,
// AXONWALL_MCP_ENABLED=true. Usage: node rate-limit-probe.mjs
// <token> [count]
import { authenticateMcpToken } from '../dist/index.js';

const token = process.argv[2] || '';
const count = Number(process.argv[3] || '1');
for (let i = 0; i < count; i++) {
  const r = authenticateMcpToken(token, '127.0.0.1');
  console.log(r.authenticated ? 'ALLOWED' : `DENIED ${r.errorStatus} ${r.errorMessage || ''}`);
}
