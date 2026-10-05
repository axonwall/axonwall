import { compileNftables } from '@axonwall/lib/compile/nft';
import { lintRuleset } from '@axonwall/lib/lint';
import type { DesiredState } from '@axonwall/lib/schemas';
import * as crypto from 'node:crypto';

export interface CompiledBundle {
  jobId: string;
  bundleHash: string;
  nftScript: string;
  warnings: string[];
  generatedAt: string;
}

export function buildArtifactBundle(jobId: string, state: DesiredState): CompiledBundle {
  // 1. Run linter
  const issues = lintRuleset(state);
  const warnings = issues.map((i) => `[${i.severity.toUpperCase()}] ${i.message}`);

  // 2. Compile to atomic nftables ruleset
  const { nftScript } = compileNftables(state);

  // 3. Compute deterministic bundle hash
  const hash = crypto.createHash('sha256').update(nftScript).digest('hex');

  return {
    jobId,
    bundleHash: hash,
    nftScript,
    warnings,
    generatedAt: new Date().toISOString(),
  };
}

async function main() {
  console.log('[Axonwall Controller] Starting Axonwall Control Plane Worker...');
  console.log('[Axonwall Controller] Monitoring config changes and apply pipeline.');

  // Heartbeat loop
  setInterval(() => {
    // Keep-alive heartbeat
  }, 10000);
}

if (process.env.NODE_ENV !== 'test') {
  main().catch((err) => {
    console.error('[Axonwall Controller] Fatal error:', err);
    process.exit(1);
  });
}
