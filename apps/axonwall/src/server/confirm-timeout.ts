// C26: shared confirm-timeout validation for the apply/import routes.
// The value reaches the daemon's commit-confirm window, so it must be
// a sane integer, not a string, zero, negative, or huge number that
// would silently mean "immediate auto-rollback" or "effectively
// permanent unconfirmed ruleset". Absent input keeps the 120s default;
// anything present but invalid throws, and both routes map that to
// HTTP 400. (Kept out of server/agent.ts on purpose: 'use server'
// modules may only export async functions, so a sync validator lives
// here instead.)
export function parseConfirmTimeoutSeconds(value: unknown): number {
  if (value === undefined || value === null || value === '') return 120;
  let num: number;
  if (typeof value === 'number') {
    num = value;
  } else if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!/^-?\d+$/.test(trimmed)) {
      throw new Error('confirmTimeoutSeconds must be an integer between 10 and 3600');
    }
    num = Number.parseInt(trimmed, 10);
  } else {
    throw new Error('confirmTimeoutSeconds must be an integer between 10 and 3600');
  }
  if (!Number.isInteger(num) || num < 10 || num > 3600) {
    throw new Error('confirmTimeoutSeconds must be an integer between 10 and 3600');
  }
  return num;
}
