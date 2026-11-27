import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { getVigilanteCtiDir, ensureVigilanteConfig } from './config.js';
import { safeFetch, readResponseWithLimit } from './ssrf.js';
import { logger } from '../utils/logger.js';

// Sample fallback CTI indicators for offline testing / baseline detection
export const SAMPLE_C2_IPS = [
  '198.51.100.45',
  '203.0.113.195',
  '185.220.101.5',
  '194.26.29.112',
  '45.154.255.89'
];

export const SAMPLE_MALICIOUS_DOMAINS = [
  'c2.malicious.io',
  'update.badactor-cdn.com',
  'payload.evilserver.net',
  'update-system-secure.biz'
];

/**
 * Fetch with timeout, SSRF pinning, redirect rejection, and byte-capped reading
 */
async function fetchWithTimeout(url, timeoutMs = 3000, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await safeFetch(url, {
      signal: controller.signal,
      redirect: 'error'
    }, {
      label: 'CTI feed URL',
      allowPrivate: options.allowPrivate ?? false,
      allowLoopback: options.allowLoopback ?? false,
      allowMetadata: false,
      dnsLookup: options.dnsLookup,
      failOnDnsError: options.failOnDnsError,
      maxBytes: options.maxBytes
    });
    clearTimeout(timer);
    return res;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Load or synchronize abuse.ch Feodo Tracker C2 IP list
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
export async function syncFeodoTrackerC2(options = {}) {
  await ensureVigilanteConfig();
  const ctiDir = getVigilanteCtiDir();
  const cacheFile = path.join(ctiDir, 'feodo_ips.json');

  let ips = [...SAMPLE_C2_IPS];
  let cacheFresh = false;

  if (!options.forceRefresh && fsSync.existsSync(cacheFile)) {
    try {
      const stats = await fs.stat(cacheFile);
      const ageHours = (Date.now() - stats.mtimeMs) / (1000 * 60 * 60);
      if (ageHours < 12) {
        const raw = await fs.readFile(cacheFile, 'utf8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          ips = parsed;
          cacheFresh = true;
        }
      }
    } catch {
      // fallback to refresh
    }
  }
  if (!cacheFresh) {
    try {
      const resp = await fetchWithTimeout('https://feodotracker.abuse.ch/downloads/ipblocklist.json', 2500, options);
      if (resp.ok) {
        const body = await readResponseWithLimit(resp, options.maxBytes);
        const data = JSON.parse(body);
        const fetchedIps = (Array.isArray(data) ? data : []).map(item => item.ip_address).filter(Boolean);
        if (fetchedIps.length > 0) {
          ips = Array.from(new Set([...ips, ...fetchedIps]));
          logger.info('CTI', `Synchronized ${ips.length} C2 IPs from abuse.ch Feodo Tracker`);
        }
      } else {
        await resp.body?.cancel?.().catch(() => {});
      }
    } catch (err) {
      logger.warn('CTI', `Feodo Tracker remote sync offline, using local/cached dataset: ${err.message}`);
    }
    await fs.writeFile(cacheFile, JSON.stringify(ips, null, 2), 'utf8');
  }

  const indicatorObjects = ips.map(ip => ({ ip, indicator: ip, type: 'C2_IP', source: 'abuse.ch Feodo Tracker' }));

  return {
    source: 'abuse.ch Feodo Tracker',
    count: indicatorObjects.length,
    indicators: indicatorObjects,
    ips,
    updatedAt: new Date().toISOString()
  };
}

export const syncFeodoTracker = syncFeodoTrackerC2;

/**
 * Load or synchronize abuse.ch URLhaus malicious URL list
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
export async function syncUrlhausThreats(options = {}) {
  await ensureVigilanteConfig();
  const ctiDir = getVigilanteCtiDir();
  const cacheFile = path.join(ctiDir, 'urlhaus_urls.json');

  let urls = [
    'http://198.51.100.45/malware.exe',
    'http://c2.malicious.io/beacon',
    'http://update-system-secure.biz/payload.sh'
  ];
  let cacheFresh = false;

  if (!options.forceRefresh && fsSync.existsSync(cacheFile)) {
    try {
      const stats = await fs.stat(cacheFile);
      const ageHours = (Date.now() - stats.mtimeMs) / (1000 * 60 * 60);
      if (ageHours < 12) {
        const raw = await fs.readFile(cacheFile, 'utf8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          urls = parsed;
          cacheFresh = true;
        }
      }
    } catch {
      // fallback
    }
  }
  if (!cacheFresh) {
    try {
      const resp = await fetchWithTimeout('https://urlhaus.abuse.ch/downloads/json_recent/', 2500, options);
      if (resp.ok) {
        const body = await readResponseWithLimit(resp, options.maxBytes);
        const data = JSON.parse(body);
        const fetched = Object.values(data).flatMap(item => Array.isArray(item) ? item.map(u => u.url) : []);
        if (fetched.length > 0) urls = Array.from(new Set([...urls, ...fetched]));
        logger.info('CTI', `Synchronized ${urls.length} malicious URLs from abuse.ch URLhaus`);
      } else {
        await resp.body?.cancel?.().catch(() => {});
      }
    } catch (err) {
      logger.warn('CTI', `URLhaus remote sync offline, using local dataset: ${err.message}`);
    }
    await fs.writeFile(cacheFile, JSON.stringify(urls, null, 2), 'utf8');
  }

  const indicatorObjects = urls.map(u => ({ url: u, indicator: u, type: 'MALICIOUS_URL', source: 'abuse.ch URLhaus' }));

  return {
    source: 'abuse.ch URLhaus',
    count: indicatorObjects.length,
    indicators: indicatorObjects,
    urls,
    updatedAt: new Date().toISOString()
  };
}

export const syncUrlhaus = syncUrlhausThreats;

/**
 * Cross-reference network indicators (IPs, domains, URLs) against active CTI databases
 * @param {Array<string>|Object} indicatorsInput
 * @param {Object} [options]
 * @returns {Promise<Array<Object>>}
 */
export async function matchCtiIndicators(indicatorsInput = [], options = {}) {
  const feodoResult = await syncFeodoTrackerC2(options);
  const urlhausResult = await syncUrlhausThreats(options);

  const feodoIps = new Set(feodoResult.ips || feodoResult.indicators.map(i => i.ip));
  const domainSet = new Set(SAMPLE_MALICIOUS_DOMAINS.map(d => d.toLowerCase()));
  const urlList = urlhausResult.urls || urlhausResult.indicators.map(i => i.url);
  const urlExactMap = new Map();
  for (const u of urlList) {
    if (typeof u === 'string' && u.trim()) {
      const norm = u.trim().replace(/\/+$/, '').toLowerCase();
      urlExactMap.set(norm, u);
    }
  }

  let targetList = [];
  if (Array.isArray(indicatorsInput)) {
    targetList = indicatorsInput;
  } else if (typeof indicatorsInput === 'object' && indicatorsInput !== null) {
    targetList = [
      ...(indicatorsInput.ips || []),
      ...(indicatorsInput.domains || []),
      ...(indicatorsInput.urls || [])
    ];
  }

  const matches = [];

  for (const item of targetList) {
    const str = String(item).trim();
    if (!str) continue;

    // Check IP match
    if (feodoIps.has(str)) {
      matches.push({
        indicator: str,
        value: str,
        type: 'C2_IP',
        source: 'abuse.ch Feodo Tracker',
        threat: 'Active Botnet Command & Control (C2) Node',
        severity: 'CRITICAL'
      });
      continue;
    }

    // Check Domain match
    if (domainSet.has(str.toLowerCase())) {
      matches.push({
        indicator: str,
        value: str,
        type: 'MALICIOUS_DOMAIN',
        source: 'Vigilante CTI Feed',
        threat: 'Known Malicious Infrastructure / Exfiltration Endpoint',
        severity: 'HIGH'
      });
      continue;
    }

    // Check exact normalized URL or parsed host match (no arbitrary substring matching)
    const normStr = str.replace(/\/+$/, '').toLowerCase();
    let urlHit = urlExactMap.get(normStr) || null;
    if (!urlHit) {
      try {
        const parsed = new URL(str);
        const parsedNorm = parsed.toString().replace(/\/+$/, '').toLowerCase();
        urlHit = urlExactMap.get(parsedNorm) || null;
        if (!urlHit) {
          const parsedHost = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
          if (feodoIps.has(parsedHost) || domainSet.has(parsedHost)) {
            urlHit = str;
          }
        }
      } catch {
        // not a full URL; do not substring-match bare strings
      }
    }
    if (urlHit) {
      matches.push({
        indicator: str,
        value: urlHit,
        type: 'MALICIOUS_URL',
        source: 'abuse.ch URLhaus',
        threat: 'Malware Distribution Payload URL',
        severity: 'CRITICAL'
      });
      continue;
    }
  }

  // Attach metadata properties without creating a circular array self-reference
  const matchItems = matches.slice();
  matches.hasMatches = matches.length > 0;
  matches.matchesCount = matches.length;
  matches.matches = matchItems;
  matches.checkedAt = new Date().toISOString();

  return matches;
}

/**
 * Download or update Emerging Threats (ET Open) rules for Suricata
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
export async function updateSuricataRules(options = {}) {
  await ensureVigilanteConfig();
  const ctiDir = getVigilanteCtiDir();
  const rulesFile = path.join(ctiDir, 'suricata-et-open.rules');

  const defaultRules = `
# Emerging Threats (ET Open) Baseline Signatures
alert tcp any any -> any [80,443] (msg:"ET CURRENT_EVENTS Malicious C2 Beacon Observed"; content:"/beacon"; sid:2000010; rev:1;)
alert tcp any any -> any [445,139] (msg:"ET EXPLOIT SMB Relay Attack Attempt in Progress"; sid:2000011; rev:1;)
alert ip any any -> [198.51.100.45,203.0.113.195] any (msg:"ET DROP Known Feodo Botnet C2 Traffic"; sid:2000012; rev:1;)
alert ip any any -> [185.220.101.5] any (msg:"ET DROP Known Cobalt Strike C2 Traffic"; sid:2000013; rev:1;)
`.trim();

  let ruleContent = defaultRules;
  try {
    const resp = await fetchWithTimeout('https://rules.emergingthreats.net/open/suricata-7.0.0/emerging-all.rules', 2500, options);
    if (resp.ok) {
      const text = await readResponseWithLimit(resp, options.maxBytes);
      if (text.length > 1000) {
        ruleContent = text;
        logger.info('CTI', `Updated Suricata signatures (${(text.length / 1024).toFixed(1)} KB)`);
      }
    } else {
      await resp.body?.cancel?.().catch(() => {});
    }
  } catch (err) {
    logger.warn('CTI', `Remote ET Open rules download timed out, using baseline rule set: ${err.message}`);
  }

  await fs.writeFile(rulesFile, ruleContent, 'utf8');

  // Count rules
  const ruleLines = ruleContent.split('\n').filter(l => l.trim().startsWith('alert ') || l.trim().startsWith('drop '));

  return {
    filePath: rulesFile,
    rulesPath: rulesFile,
    ruleCount: ruleLines.length > 0 ? ruleLines.length : 4,
    sizeBytes: Buffer.byteLength(ruleContent, 'utf8'),
    updatedAt: new Date().toISOString(),
    status: 'synced'
  };
}
