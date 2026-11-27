import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  getVigilanteZapDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { assertSafeOutboundTarget, safeFetch, readResponseWithLimit } from './ssrf.js';
import { logger } from '../utils/logger.js';

export const ZAP_PROFILES = [
  {
    id: 'spider',
    name: '🕷️  Web Crawler & Attack Surface Spider',
    description: 'Map web application endpoints, URLs, forms, and parameter attack vectors',
    scanType: 'spider'
  },
  {
    id: 'active',
    name: '⚡ Active DAST Vulnerability Scan',
    description: 'Inject payloads to test for SQLi, XSS, SSRF, IDOR, and OWASP Top 10 vulnerabilities',
    scanType: 'active'
  },
  {
    id: 'quick',
    name: '⏱️  Quick Baseline DAST Audit',
    description: 'Passive spider and rapid security headers / TLS checks',
    scanType: 'passive'
  }
];

/**
 * Check whether ZAP API is reachable (in-cluster or local)
 * @param {string} [zapBaseUrl='http://zap.vigilante.local']
 * @param {string} [apiKey='']
 * @returns {Promise<{ reachable: boolean, version: string }>}
 */
export async function checkZapAvailable(zapBaseUrl = 'http://zap.vigilante.local', apiKey = '', opts = {}) {
  const isDefaultUrl = zapBaseUrl === 'http://zap.vigilante.local';
  const validatedTarget = await assertSafeOutboundTarget(zapBaseUrl, {
    label: 'ZAP base URL',
    allowPrivate: true,
    allowLoopback: true,
    allowMetadata: false,
    dnsLookup: opts.dnsLookup,
    failOnDnsError: opts.failOnDnsError ?? !isDefaultUrl
  });
  if (!validatedTarget.addresses || validatedTarget.addresses.length === 0) {
    return { reachable: false, version: 'offline / emulation' };
  }
  const baseStr = validatedTarget.url.toString().replace(/\/+$/, '');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2000);
  try {
    const headers = {};
    if (apiKey) headers['X-ZAP-API-Key'] = apiKey;

    const res = await safeFetch(`${baseStr}/JSON/core/view/version/`, {
      signal: controller.signal,
      redirect: 'error',
      headers
    }, {
      validatedTarget,
      allowPrivate: true,
      allowLoopback: true,
      allowMetadata: false,
      maxBytes: opts.maxBytes
    });

    if (res.ok) {
      const data = JSON.parse(await readResponseWithLimit(res, opts.maxBytes));
      return { reachable: true, version: data.version || 'unknown' };
    }
    await res.body?.cancel?.().catch(() => {});
  } catch {
    // unreachable
  } finally {
    clearTimeout(timeout);
  }
  return { reachable: false, version: 'offline / emulation' };
}

/**
 * Trigger or emulate a ZAP security scan
 * @param {string} targetUrl 
 * @param {string} [profileId='spider'] 
 * @param {object} [opts={}]
 * @returns {Promise<object>}
 */
export async function runZapScan(targetUrl, profileId = 'spider', opts = {}) {
  const { url: safeTarget, hostname: safeTargetHost } = await assertSafeOutboundTarget(targetUrl, {
    label: 'ZAP targetUrl',
    allowPrivate: opts.allowPrivate,
    allowLoopback: opts.allowLoopback,
    allowMetadata: false,
    dnsLookup: opts.dnsLookup,
    failOnDnsError: opts.failOnDnsError
  });
  const normalizedTargetUrl = safeTarget.toString();

  await ensureVigilanteConfig();
  const zapDir = getVigilanteZapDir();
  const profile = ZAP_PROFILES.find((p) => p.id === profileId) || ZAP_PROFILES[0];
  const zapBaseUrl = opts.zapBaseUrl || 'http://zap.vigilante.local';
  const isDefaultZapBase = zapBaseUrl === 'http://zap.vigilante.local';
  const safeZapTarget = await assertSafeOutboundTarget(zapBaseUrl, {
    label: 'ZAP base URL',
    allowPrivate: true,
    allowLoopback: true,
    allowMetadata: false,
    dnsLookup: opts.dnsLookup,
    failOnDnsError: opts.failOnDnsError ?? !isDefaultZapBase
  });
  const cleanZapBase = safeZapTarget.url.toString().replace(/\/+$/, '');
  const apiKey = opts.apiKey || '';

  const timestamp = new Date().toISOString();
  const scanId = `zap_${normalizedTargetUrl.replace(/[^a-zA-Z0-9_.-]/g, '_')}_${Date.now()}`;
  let alerts = [];
  let urls = [];

  const zapStatus = await checkZapAvailable(cleanZapBase, apiKey, opts);

  if (zapStatus.reachable) {
    try {
      const headers = {};
      if (apiKey) headers['X-ZAP-API-Key'] = apiKey;

      const fetchZapJson = async (endpoint) => {
        const res = await safeFetch(`${cleanZapBase}${endpoint}`, {
          method: 'GET',
          redirect: 'error',
          signal: AbortSignal.timeout(5000),
          headers
        }, {
          validatedTarget: safeZapTarget,
          allowPrivate: true,
          allowLoopback: true,
          allowMetadata: false,
          maxBytes: opts.maxBytes
        });
        if (!res.ok) {
          await res.body?.cancel?.().catch(() => {});
          throw new Error(`ZAP API ${endpoint} returned HTTP ${res.status}`);
        }
        return JSON.parse(await readResponseWithLimit(res, opts.maxBytes));
      };

      // Start spider (also primes URL tree for active scan)
      const spiderData = await fetchZapJson(`/JSON/spider/action/scan/?url=${encodeURIComponent(normalizedTargetUrl)}`);
      const spiderId = spiderData.scan;

      // Poll spider briefly (up to 5s)
      const maxPolls = profile.scanType === 'passive' ? 2 : 5;
      for (let i = 0; i < maxPolls; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const sdata = await fetchZapJson(`/JSON/spider/view/status/?scanId=${encodeURIComponent(String(spiderId))}`);
        if (String(sdata.status) === '100') break;
      }

      // If active scan requested, trigger /JSON/ascan/action/scan/ and poll status
      if (profile.scanType === 'active') {
        const ascanData = await fetchZapJson(`/JSON/ascan/action/scan/?url=${encodeURIComponent(normalizedTargetUrl)}`);
        const ascanId = ascanData.scan;
        for (let i = 0; i < 10; i++) {
          await new Promise((r) => setTimeout(r, 1000));
          const adata = await fetchZapJson(`/JSON/ascan/view/status/?scanId=${encodeURIComponent(String(ascanId))}`);
          if (String(adata.status) === '100') break;
        }
      }

      // Fetch alerts and discovered URLs
      const alertData = await fetchZapJson(`/JSON/core/view/alerts/?baseurl=${encodeURIComponent(normalizedTargetUrl)}`);
      alerts = alertData.alerts || [];
      try {
        const urlsData = await fetchZapJson(`/JSON/core/view/urls/?baseurl=${encodeURIComponent(normalizedTargetUrl)}`);
        urls = urlsData.urls || [];
      } catch {
        // optional endpoint
      }
    } catch (err) {
      logger.warn('ZAP', `Error calling ZAP API: ${err.message}`);
    }
  } else {
    // Synthetic emulation fallback
    alerts = [
      {
        alert: 'Missing Anti-clickjacking Header',
        risk: 'Medium',
        confidence: 'Medium',
        url: normalizedTargetUrl,
        param: 'X-Frame-Options',
        solution: 'Configure X-Frame-Options or Content-Security-Policy frame-ancestors'
      },
      {
        alert: 'Strict-Transport-Security Header Not Set',
        risk: 'Low',
        confidence: 'High',
        url: normalizedTargetUrl,
        solution: 'Enable HTTP Strict Transport Security (HSTS) with max-age=31536000'
      }
    ];
    urls = [normalizedTargetUrl];
  }

  // When ZAP is unreachable, the alerts above are the synthetic emulation
  // fallback, not observed findings. zapReachable already implied it, but
  // the persisted/signed record now states it explicitly like the other
  // scanner records.
  const record = {
    id: scanId,
    target: normalizedTargetUrl,
    profile: profile.id,
    timestamp,
    synthetic: !zapStatus.reachable,
    runner: zapStatus.reachable ? 'api' : 'none',
    zapReachable: zapStatus.reachable,
    zapVersion: zapStatus.version,
    alerts,
    urls
  };

  const filePath = path.join(zapDir, `${scanId}.json`);
  await fs.writeFile(filePath, JSON.stringify(record, null, 2), 'utf8');

  // GPG sign if configured
  await autoSignIfConfigured(filePath);

  // Evidence file
  try {
    await saveEvidenceFile('scans', safeTargetHost, `${scanId}.json`, record);
  } catch (err) {
    logger.warn('ZAP', `Could not save evidence file: ${err.message}`);
  }

  return { ...record, filePath };
}

/**
 * List saved ZAP scans
 * @returns {Promise<Array<object>>}
 */
export async function listSavedZapScans() {
  await ensureVigilanteConfig();
  const zapDir = getVigilanteZapDir();
  try {
    const files = await fs.readdir(zapDir);
    const results = [];
    for (const f of files) {
      if (f.endsWith('.json') && !f.endsWith('.sig') && !f.endsWith('.asc')) {
        const fullPath = path.join(zapDir, f);
        try {
          const content = await fs.readFile(fullPath, 'utf8');
          const parsed = JSON.parse(content);
          results.push({
            id: parsed.id || f.replace('.json', ''),
            target: parsed.target || 'unknown',
            profile: parsed.profile || 'spider',
            timestamp: parsed.timestamp || '',
            alertCount: (parsed.alerts || []).length,
            filePath: fullPath
          });
        } catch {
          // ignore corrupted files
        }
      }
    }
    return results.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
  } catch {
    return [];
  }
}
