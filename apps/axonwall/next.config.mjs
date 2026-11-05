import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const cspHeader = `
  default-src 'self';
  script-src 'self' 'unsafe-eval' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
`;

const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  transpilePackages: ['nastymap'],
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
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: cspHeader.replace(/\n/g, ''),
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains',
          }
        ],
      },
    ];
  },
};

export default nextConfig;
