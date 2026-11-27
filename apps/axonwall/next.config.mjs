import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env.NODE_ENV === 'production';

// In local dev mode on non-appliance hosts, provision <repo>/.axonwall-dev/etc/axonwall.env
// with a random per-workstation JWT_SECRET so Edge middleware and Server Actions share one secret
// without storing any hardcoded secret in source control or mutating host /etc/axonwall.
if ((!isProduction || process.env.AXONWALL_DEV === '1') && !fs.existsSync('/etc/axonwall/.axonwall-os')) {
  const repoRoot = path.resolve(__dirname, '../..');
  const devRoot = process.env.AXONWALL_DEV_DIR
    ? path.resolve(process.env.AXONWALL_DEV_DIR)
    : path.join(repoRoot, '.axonwall-dev');
  const etcDir = path.join(devRoot, 'etc');
  const envFile = path.join(etcDir, 'axonwall.env');
  try {
    fs.mkdirSync(etcDir, { recursive: true, mode: 0o700 });
    let jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret && fs.existsSync(envFile)) {
      for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('JWT_SECRET=')) {
          jwtSecret = trimmed.slice('JWT_SECRET='.length).trim();
          break;
        }
      }
    }
    if (!jwtSecret) {
      jwtSecret = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(envFile, `JWT_SECRET=${jwtSecret}\n`, { mode: 0o600 });
    }
    if (!process.env.JWT_SECRET) {
      process.env.JWT_SECRET = jwtSecret;
    }
  } catch {}
}

const buildCspHeader = (frameAncestors) => `
  default-src 'self';
  script-src 'self' 'unsafe-inline'${isProduction ? '' : " 'unsafe-eval'"};
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  connect-src 'self';
  frame-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors ${frameAncestors};
  ${isProduction ? 'upgrade-insecure-requests;' : ''}
`.replace(/\s+/g, ' ').trim();

const buildSecurityHeaders = (frameAncestors, xFrameOptions) => {
  const headers = [
    { key: 'Content-Security-Policy', value: buildCspHeader(frameAncestors) },
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'X-Frame-Options', value: xFrameOptions },
    { key: 'X-XSS-Protection', value: '0' },
    { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
    { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  ];
  if (isProduction) {
    headers.push({
      key: 'Strict-Transport-Security',
      value: 'max-age=31536000; includeSubDomains',
    });
  }
  return headers;
};

const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  transpilePackages: ['nastymap', '@axonwall/lib', 'vigilante_lib'],
  experimental: {
    serverActions: {
      bodySizeLimit: '2mb',
    },
  },

  webpack: (config) => {
    // Resolve the `@/` tsconfig alias explicitly. Next's tsconfig-paths
    // handling fails to resolve `@/server/*` for the first pages that
    // import each server-action module (Module not found, while later
    // importers of the same module resolve fine); a plain webpack alias
    // makes resolution deterministic for every importer.
    config.resolve.alias = { ...config.resolve.alias, '@': path.join(__dirname, 'src') };
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
    };
    return config;
  },
  async headers() {
    return [
      {
        source: '/((?!api/docs-bundle(?:/|$)).*)',
        headers: buildSecurityHeaders("'none'", 'DENY'),
      },
      {
        source: '/api/docs-bundle/:path*',
        headers: buildSecurityHeaders("'self'", 'SAMEORIGIN'),
      },
    ];
  },
};

export default nextConfig;
