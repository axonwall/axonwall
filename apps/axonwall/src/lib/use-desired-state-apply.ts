'use client';

import { useCallback, useEffect, useRef } from 'react';
import {
  applyDesiredState,
  getDesiredStateFingerprint,
} from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

export type ApplyDesiredStateResult = {
  success: boolean;
  message: string;
  nftScript: string;
  warnings: string[];
};

/**
 * C2: thread the state-version fingerprint through a page's applies.
 *
 * The server refuses an apply whose expectedFingerprint no longer matches
 * the on-disk config, which is what stops a same-slice cross-tab lost
 * update (tab A adds alias X; tab B, loaded earlier, adds alias Y — B's
 * apply is refused instead of silently reverting X). The fingerprint has
 * to be the one the page loaded with, so this hook captures it at mount,
 * passes it on every apply, and refreshes it after a successful apply
 * (a successful apply rewrites the on-disk config, so the stored
 * fingerprint would otherwise trip the precondition on the page's own
 * next save). When the fingerprint cannot be fetched the apply runs
 * without the precondition, as before — never worse than today.
 *
 * A fingerprint mismatch throws the server's "Configuration changed
 * since it was loaded…" error; callers surface it through their usual
 * error channel and must reload before retrying.
 */
export function useDesiredStateApply() {
  const fingerprintRef = useRef<string | null>(null);

  const refreshFingerprint = useCallback(async () => {
    try {
      const { fingerprint } = await getDesiredStateFingerprint();
      fingerprintRef.current = fingerprint;
    } catch {
      // Leave the previous fingerprint (or none) in place.
    }
  }, []);

  useEffect(() => {
    void refreshFingerprint();
  }, [refreshFingerprint]);

  const getFingerprint = useCallback(() => fingerprintRef.current, []);

  const applyState = useCallback(
    async (
      state: DesiredState,
      confirmTimeoutSeconds = 120
    ): Promise<ApplyDesiredStateResult> => {
      const res = await applyDesiredState(
        state,
        confirmTimeoutSeconds,
        fingerprintRef.current ? { expectedFingerprint: fingerprintRef.current } : undefined
      );
      await refreshFingerprint();
      return res;
    },
    [refreshFingerprint]
  );

  return { applyState, refreshFingerprint, getFingerprint };
}
