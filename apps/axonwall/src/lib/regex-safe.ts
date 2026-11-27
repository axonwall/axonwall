/**
 * Bounded regex compiler & ReDoS guard for client-side live filters (SEC-L20).
 */

export const MAX_FILTER_REGEX_LENGTH = 128;

interface GroupFrame {
  hasQuantifierInside: boolean;
  hasAlternation: boolean;
}

function parseBraceQuantifier(pattern: string, startIdx: number): { length: number; repeating: boolean } | null {
  const rest = pattern.slice(startIdx);
  const match = /^\{(\d+)(?:,(\d*))?\}/.exec(rest);
  if (!match) return null;
  const min = Number.parseInt(match[1], 10);
  const maxStr = match[2];
  // {0} or {1} or {0,1} does not repeat more than once; anything unbounded or >=2 repeats.
  const repeating = maxStr === undefined ? min > 1 : maxStr === '' || Number.parseInt(maxStr, 10) > 1;
  return { length: match[0].length, repeating };
}

/**
 * Checks whether a regex pattern is <= 128 characters and free of nested
 * quantifiers, stacked quantifiers, quantified alternations, and backreferences.
 */
export function isSafeFilterRegex(pattern: string): boolean {
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > MAX_FILTER_REGEX_LENGTH) {
    return false;
  }

  const stack: GroupFrame[] = [];
  let inCharClass = false;
  let charClassStart = false;
  let prevWasQuantifier = false;
  let justClosedGroup: GroupFrame | null = null;

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];

    if (ch === '\\') {
      if (i + 1 >= pattern.length) return false;
      const next = pattern[i + 1];
      if (!inCharClass && next >= '1' && next <= '9') {
        // Backreferences can cause exponential matching.
        return false;
      }
      i++;
      prevWasQuantifier = false;
      justClosedGroup = null;
      charClassStart = false;
      continue;
    }

    if (inCharClass) {
      if (ch === ']' && !charClassStart) {
        inCharClass = false;
      }
      charClassStart = false;
      continue;
    }

    if (ch === '[') {
      inCharClass = true;
      charClassStart = true;
      prevWasQuantifier = false;
      justClosedGroup = null;
      continue;
    }

    if (ch === '(') {
      stack.push({ hasQuantifierInside: false, hasAlternation: false });
      prevWasQuantifier = false;
      justClosedGroup = null;
      continue;
    }

    if (ch === ')') {
      const closed = stack.pop();
      if (!closed) return false;
      if (closed.hasAlternation && stack.length > 0) {
        stack[stack.length - 1].hasAlternation = true;
      }
      justClosedGroup = closed;
      prevWasQuantifier = false;
      continue;
    }

    if (ch === '|') {
      if (stack.length > 0) {
        stack[stack.length - 1].hasAlternation = true;
      }
      prevWasQuantifier = false;
      justClosedGroup = null;
      continue;
    }

    if (ch === '*' || ch === '+' || ch === '?' || ch === '{') {
      let quantifierLen = 1;
      let repeating = ch === '*' || ch === '+';
      let isLazyModifier = false;

      if (ch === '{') {
        const brace = parseBraceQuantifier(pattern, i);
        if (!brace) {
          // Literal '{'
          prevWasQuantifier = false;
          justClosedGroup = null;
          continue;
        }
        quantifierLen = brace.length;
        repeating = brace.repeating;
      } else if (ch === '?' && prevWasQuantifier) {
        isLazyModifier = true;
      }

      if (isLazyModifier) {
        // Lazy '?' following *, +, ?, or {m,n} keeps prevWasQuantifier true
        // so another quantifier directly after (e.g. a+?+) is still caught.
        continue;
      }

      if (prevWasQuantifier) {
        return false;
      }

      if (repeating) {
        if (justClosedGroup && (justClosedGroup.hasQuantifierInside || justClosedGroup.hasAlternation)) {
          return false;
        }
        for (const frame of stack) {
          frame.hasQuantifierInside = true;
        }
      }

      prevWasQuantifier = true;
      justClosedGroup = null;
      i += quantifierLen - 1;
      continue;
    }

    prevWasQuantifier = false;
    justClosedGroup = null;
  }

  return !inCharClass && stack.length === 0;
}

/**
 * Compiles a bounded, ReDoS-guarded case-insensitive RegExp, or returns null
 * if the pattern exceeds 128 characters, contains unsafe quantifiers, or is invalid.
 */
export function safeCompileFilterRegex(pattern: string): RegExp | null {
  if (!isSafeFilterRegex(pattern)) return null;
  try {
    return new RegExp(pattern, 'i');
  } catch {
    return null;
  }
}

export function matchFilterHaystack(haystackLower: string, rawQuery: string): boolean {
  const q = rawQuery.trim();
  if (!q) return true;

  const neg = q.startsWith('!');
  const expr = neg ? q.slice(1).trim() : q;
  if (!expr) return true;

  let matched = false;
  if (expr.startsWith('/') && expr.endsWith('/') && expr.length > 2) {
    const pattern = expr.slice(1, -1);
    const re = safeCompileFilterRegex(pattern);
    if (re) {
      matched = re.test(haystackLower);
    } else {
      matched = haystackLower.includes(pattern.toLowerCase());
    }
  } else {
    const terms = expr.toLowerCase().split(/\s+/).filter(Boolean);
    matched = terms.every((t) => haystackLower.includes(t));
  }
  return neg ? !matched : matched;
}
