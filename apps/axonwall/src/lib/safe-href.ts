/**
 * URL sanitization helpers for console links and cross-origin portal redirects.
 */

const CONTROL_OR_WHITESPACE_RE = /[\u0000-\u001f\u007f\s]/;

/**
 * Validates that a URL is an absolute `http:` or `https:` URL.
 * Rejects `javascript:`, `data:`, `vbscript:`, `file:`, relative paths, and
 * malformed URLs, falling back to `fallback` (or `'#'` if fallback is unsafe).
 */
export function safeHttpHref(rawUrl: string | null | undefined, fallback = '#'): string {
  const candidate = typeof rawUrl === 'string' ? rawUrl.trim() : '';
  if (candidate && !CONTROL_OR_WHITESPACE_RE.test(candidate)) {
    try {
      const parsed = new URL(candidate);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return candidate;
      }
    } catch {
      // Fall through to fallback
    }
  }
  if (fallback === '#') return '#';
  const safeFallback = typeof fallback === 'string' ? fallback.trim() : '';
  if (safeFallback && !CONTROL_OR_WHITESPACE_RE.test(safeFallback)) {
    try {
      const parsedFallback = new URL(safeFallback);
      if (parsedFallback.protocol === 'http:' || parsedFallback.protocol === 'https:') {
        return safeFallback;
      }
    } catch {
      // Fall through
    }
  }
  return '#';
}

/**
 * Validates either an internal root-relative app path (`/vpn`, `/login`) or an
 * absolute `http:`/`https:` URL. Rejects protocol-relative (`//foo`), backslash
 * (`/\foo`), and dangerous schemes (`javascript:`, `data:`).
 */
export function safeAppHref(rawUrl: string | null | undefined, fallback = '/'): string {
  const candidate = typeof rawUrl === 'string' ? rawUrl.trim() : '';
  if (candidate && !CONTROL_OR_WHITESPACE_RE.test(candidate)) {
    if (candidate.startsWith('/') && !candidate.startsWith('//') && !candidate.startsWith('/\\')) {
      return candidate;
    }
    const httpCandidate = safeHttpHref(candidate, '#');
    if (httpCandidate !== '#') {
      return httpCandidate;
    }
  }
  return fallback;
}

/**
 * Returns true when `href` is an absolute `http://` or `https://` URL that should
 * be rendered with a native `<a href>` rather than Next.js `<Link>`.
 */
export function isAbsoluteHttpHref(href: string | null | undefined): boolean {
  return typeof href === 'string' && /^https?:\/\//i.test(href.trim());
}
