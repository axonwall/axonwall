export const ONLINE_DOCS_BASE_URL = 'https://axonwall.com/docs';

const SLUG_SEGMENT_PATTERN = /^[a-z0-9-]+$/;

export function buildOnlineDocsUrl(slug?: string[], hash?: string): string {
  const cleanSegments = (slug || []).filter((s) => SLUG_SEGMENT_PATTERN.test(s));
  const basePath =
    cleanSegments.length > 0
      ? `${ONLINE_DOCS_BASE_URL}/${cleanSegments.join('/')}`
      : ONLINE_DOCS_BASE_URL;
  if (!hash) return basePath;
  const cleanHash = hash.startsWith('#') ? hash.slice(1) : hash;
  return SLUG_SEGMENT_PATTERN.test(cleanHash) ? `${basePath}#${cleanHash}` : basePath;
}
