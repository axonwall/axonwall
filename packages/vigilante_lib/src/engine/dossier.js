import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  getVigilanteDossiersDir,
  getVigilanteNmapsDir,
  getVigilanteOobscansDir,
  getVigilanteReconDir,
  getVigilanteNucleiDir,
  getVigilanteTrivyDir,
  getVigilanteNetexecDir,
  getVigilanteZapDir,
  getVigilanteBloodhoundDir,
  getVigilantePcapDir,
  ensureVigilanteConfig,
  getHostEvidenceDir,
  sanitizePathComponent,
  resolvePathInside
} from './config.js';
import { listSavedXmlScans } from './nmap-xml.js';
import { parseSuricataEve } from './traffic.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { logger } from '../utils/logger.js';

/**
 * Calculate a normalized 0–100 Composite Risk Score and Risk Tier
 * @param {Object} findings
 * @returns {{ score: number, tier: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'CLEAN', color: string }}
 */
export function calculateRiskScore(findings = {}) {
  let score = 0;

  // Nuclei / CVE findings
  const nucleiCritical = findings.nuclei?.critical || 0;
  const nucleiHigh = findings.nuclei?.high || 0;
  const nucleiMedium = findings.nuclei?.medium || 0;
  score += nucleiCritical * 35;
  score += nucleiHigh * 20;
  score += nucleiMedium * 8;

  // Trivy findings
  const trivyCritical = findings.trivy?.critical || 0;
  const trivyHigh = findings.trivy?.high || 0;
  const trivySecrets = findings.trivy?.secrets || 0;
  score += trivyCritical * 30;
  score += trivyHigh * 15;
  score += trivySecrets * 25;

  // NetExec / Credential / Protocol exposures
  if (findings.netexec?.signingDisabled) score += 25;
  if (findings.netexec?.guestAuthAllowed) score += 20;
  if (findings.netexec?.nullSession) score += 15;

  // OOB / IPMI exposures
  if (findings.oobscan?.isBmc) score += 15;
  if (findings.oobscan?.rakpDumped) score += 35;

  // ZAP alerts
  const zapHigh = findings.zap?.high || 0;
  const zapMedium = findings.zap?.medium || 0;
  score += zapHigh * 25;
  score += zapMedium * 10;

  // BloodHound identity compromise
  if (findings.bloodhound?.tier0Compromised) score += 50;
  else if (findings.bloodhound?.compromised) score += 30;

  // Suricata / Network IDS
  if (findings.traffic?.criticalAlerts) score += 40;
  else if (findings.traffic?.highAlerts) score += 20;

  // Cap at 100
  const normalizedScore = Math.min(100, Math.round(score));

  let tier = 'CLEAN';
  let color = 'green';

  if (normalizedScore >= 80) {
    tier = 'CRITICAL';
    color = 'red';
  } else if (normalizedScore >= 55) {
    tier = 'HIGH';
    color = 'yellow';
  } else if (normalizedScore >= 30) {
    tier = 'MEDIUM';
    color = 'cyan';
  } else if (normalizedScore > 0) {
    tier = 'LOW';
    color = 'blue';
  }

  return { score: normalizedScore, tier, color };
}

/**
 * Scan local directory for JSON files matching a predicate or target
 * @private
 */
async function loadMatchingJsonFiles(dir, filterFn) {
  if (!fsSync.existsSync(dir)) return [];
  try {
    const files = await fs.readdir(dir);
    const results = [];
    for (const f of files) {
      if (f.endsWith('.json')) {
        try {
          const raw = await fs.readFile(path.join(dir, f), 'utf8');
          const data = JSON.parse(raw);
          if (!filterFn || filterFn(data, f)) {
            results.push(data);
          }
        } catch {
          // ignore corrupted files
        }
      }
    }
    return results;
  } catch {
    return [];
  }
}

/**
 * Build or refresh a Unified Host Dossier for a target IP/hostname
 * by aggregating scan evidence across all engines
 * @param {string} target - Target IP address or hostname
 * @param {Object} [options]
 * @returns {Promise<Object>} Unified Host Dossier
 */
export async function buildHostDossier(target, options = {}) {
  await ensureVigilanteConfig();
  const dossiersDir = getVigilanteDossiersDir();
  const cleanTarget = sanitizePathComponent(target);
  const normalizedTarget = String(target || '').trim();

  const dossier = {
    target: normalizedTarget,
    cleanTarget,
    updatedAt: new Date().toISOString(),
    network: {
      openPorts: [],
      osGuessed: 'Unknown',
      services: [],
      httpEndpoints: []
    },
    vulnerabilities: {
      cves: [],
      misconfigs: [],
      secrets: [],
      zapAlerts: []
    },
    identity: {
      bloodhoundAlerts: [],
      kerberosExposures: [],
      compromisedAccounts: []
    },
    outOfBand: {
      detected: false,
      details: null
    },
    traffic: {
      alertCount: 0,
      recentAlerts: []
    },
    remediations: [],
    mitreTechniques: []
  };

  // 1. Ingest Nmap evidence (saved JSON records and parsed Nmap XML reports)
  const nmaps = await loadMatchingJsonFiles(getVigilanteNmapsDir(), d =>
    d.target === normalizedTarget || (d.hosts && d.hosts.some(h => h.ip === normalizedTarget || h.hostname === normalizedTarget))
  );
  let xmlScans = [];
  try {
    xmlScans = await listSavedXmlScans();
  } catch {
    xmlScans = [];
  }
  const allNmaps = [...nmaps, ...xmlScans.filter(d =>
    d.target === normalizedTarget || (d.hosts && d.hosts.some(h => h.ip === normalizedTarget || h.hostname === normalizedTarget))
  )];
  for (const nmapReport of allNmaps) {
    const match = (nmapReport.hosts || []).find(h => h.ip === normalizedTarget || h.hostname === normalizedTarget);
    if (match) {
      if (Array.isArray(match.openPorts)) {
        for (const portNum of match.openPorts) {
          const num = Number(portNum);
          if (Number.isInteger(num) && num > 0) dossier.network.openPorts.push(num);
        }
      }
      if (Array.isArray(match.ports)) {
        for (const p of match.ports) {
          if (typeof p === 'number') {
            if (Number.isInteger(p) && p > 0) dossier.network.openPorts.push(p);
          } else if (p && (!p.state || p.state === 'open')) {
            const num = Number(p.portid ?? p.port);
            if (Number.isInteger(num) && num > 0) dossier.network.openPorts.push(num);
          }
        }
      }
      const guessedOs = match.os || match.bestOsMatch?.name || match.osMatches?.[0]?.name;
      if (guessedOs && dossier.network.osGuessed === 'Unknown') {
        dossier.network.osGuessed = guessedOs;
      }
    }
  }

  // 2. Ingest Recon (Naabu & Httpx) evidence
  const recons = await loadMatchingJsonFiles(getVigilanteReconDir(), d =>
    d.target === normalizedTarget ||
    (d.openPorts && d.openPorts.some(p => p.host === normalizedTarget)) ||
    (d.naabu?.ports && d.naabu.ports.some(p => p.host === normalizedTarget))
  );
  for (const r of recons) {
    const reconPorts = r.openPorts || r.naabu?.ports || [];
    for (const p of reconPorts) {
      const portNum = Number(typeof p === 'object' ? p?.port : p);
      const portHost = typeof p === 'object' ? (p?.host || r.target) : r.target;
      if (portHost === normalizedTarget && Number.isInteger(portNum) && portNum > 0 && !dossier.network.openPorts.includes(portNum)) {
        dossier.network.openPorts.push(portNum);
      }
    }
    const reconWebs = r.webServices || r.httpx?.results || [];
    for (const h of reconWebs) {
      if (h.host === normalizedTarget || r.target === normalizedTarget || h.url?.includes(normalizedTarget)) {
        dossier.network.httpEndpoints.push({
          url: h.url,
          status: h.status ?? h.statusCode ?? null,
          title: h.title,
          tech: h.tech || []
        });
      }
    }
  }

  // 3. Ingest Nuclei findings
  const nucleiScans = await loadMatchingJsonFiles(getVigilanteNucleiDir(), d =>
    d.target === normalizedTarget ||
    (d.findings && d.findings.some(f => f.host?.includes(normalizedTarget) || f.matchedAt?.includes(normalizedTarget) || f.matched?.includes(normalizedTarget)))
  );
  for (const ns of nucleiScans) {
    const matchedFindings = (ns.findings || []).filter(f =>
      ns.target === normalizedTarget || f.host?.includes(normalizedTarget) || f.matchedAt?.includes(normalizedTarget) || f.matched?.includes(normalizedTarget)
    );
    for (const mf of matchedFindings) {
      dossier.vulnerabilities.cves.push({
        source: 'nuclei',
        id: mf.templateId,
        name: mf.name,
        severity: mf.severity,
        cveId: mf.cveId,
        cvssScore: mf.cvssScore,
        description: mf.description,
        remediation: mf.remediation
      });
      if (mf.cveId) {
        dossier.remediations.push(`Patch software component: ${mf.cveId} (${mf.name})`);
      }
      dossier.mitreTechniques.push('T1190'); // Exploit Public-Facing Application
    }
  }

  // 4. Ingest Trivy findings
  const trivyAudits = await loadMatchingJsonFiles(getVigilanteTrivyDir(), d =>
    d.target === normalizedTarget || d.target?.includes(normalizedTarget)
  );
  for (const ta of trivyAudits) {
    const vulns = ta.vulnerabilities || ta.findings?.vulnerabilities || [];
    if (vulns.length > 0) {
      dossier.vulnerabilities.cves.push(...vulns.map(v => ({
        source: 'trivy',
        id: v.cveId || v.id,
        severity: v.severity,
        package: v.pkgName || v.package,
        fixedVersion: v.fixedVersion
      })));
    }
    const misconfigs = ta.misconfigurations || ta.findings?.misconfigurations || [];
    if (misconfigs.length > 0) {
      dossier.vulnerabilities.misconfigs.push(...misconfigs);
    }
    const secrets = ta.secrets || ta.findings?.secrets || [];
    if (secrets.length > 0) {
      dossier.vulnerabilities.secrets.push(...secrets);
      dossier.mitreTechniques.push('T1552'); // Unsecured Credentials
      dossier.remediations.push(`Rotate leaked secret found in container/manifest: ${ta.target}`);
    }
  }

  // 5. Ingest oobscan findings
  const oobscans = await loadMatchingJsonFiles(getVigilanteOobscansDir(), d =>
    d.target === normalizedTarget || (d.bmcs && d.bmcs.some(b => b.ip === normalizedTarget))
  );
  for (const os of oobscans) {
    const bmc = (os.bmcs || os.parsed?.bmcs || []).find(b => b.ip === normalizedTarget);
    if (bmc) {
      dossier.outOfBand.detected = true;
      dossier.outOfBand.details = bmc;
      dossier.mitreTechniques.push('T1584'); // Compromise Infrastructure
      dossier.remediations.push(`Isolate BMC/IPMI interface for ${normalizedTarget} on a dedicated management VLAN.`);
    }
  }

  // 6. Ingest NetExec findings
  const netexecs = await loadMatchingJsonFiles(getVigilanteNetexecDir(), d =>
    d.target === normalizedTarget ||
    (d.findings && d.findings.some(r => r.ip === normalizedTarget || r.hostname === normalizedTarget || r.host === normalizedTarget)) ||
    (d.results && d.results.some(r => r.host === normalizedTarget || r.ip === normalizedTarget))
  );
  let netexecSigningDisabled = false;
  let netexecGuestAllowed = false;
  let netexecNullSession = false;

  for (const ne of netexecs) {
    const neFindings = ne.findings || ne.results || [];
    for (const r of neFindings) {
      const findingHost = r.ip || r.hostname || r.host;
      if (findingHost === normalizedTarget || ne.target === normalizedTarget) {
        const signingDisabled =
          r.smbSigning === false ||
          r.isVulnerableToRelay === true ||
          /^(false|disabled)$/i.test(String(r.smbSigning || ''));
        if (signingDisabled) {
          netexecSigningDisabled = true;
          dossier.mitreTechniques.push('T1557.001'); // LLMNR/NBT-NS Poisoning and SMB Relay
          dossier.remediations.push(`Enforce SMB Signing on ${normalizedTarget} to prevent NTLM relay attacks.`);
        }
        if (r.guestAuth) netexecGuestAllowed = true;
        if (r.nullSession) netexecNullSession = true;
      }
    }
  }

  // 7. Ingest ZAP alerts
  const zaps = await loadMatchingJsonFiles(getVigilanteZapDir(), d =>
    d.target === normalizedTarget || d.target?.includes(normalizedTarget)
  );
  for (const z of zaps) {
    for (const a of z.alerts || []) {
      dossier.vulnerabilities.zapAlerts.push(a);
      if (a.risk === 'High') {
        dossier.remediations.push(`Remediate web application flaw: ${a.alert || a.name} (${a.solution || 'Sanitize input'})`);
      }
    }
  }

  // 8. Ingest BloodHound data
  const bhs = await loadMatchingJsonFiles(getVigilanteBloodhoundDir(), d =>
    d.parsed?.computers?.some(c => c.name?.includes(target)) ||
    d.parsed?.users?.some(u => u.name?.includes(target))
  );
  let bhCompromised = false;
  let bhTier0 = false;
  for (const b of bhs) {
    if (b.correlation?.tier0Compromises?.length > 0) bhTier0 = true;
    if (b.correlation?.compromisedAccounts?.length > 0) bhCompromised = true;
    for (const alert of b.parsed?.attackPathAlerts || []) {
      if (alert.target?.includes(target)) {
        dossier.identity.bloodhoundAlerts.push(alert);
      }
    }
  }

  // 9. Ingest Traffic alerts (supplied options or Suricata/traffic artifacts in pcapDir)
  const normalizeTrafficSeverity = (sev) => {
    if (sev === 1 || String(sev).toLowerCase() === 'critical') return 'critical';
    if (sev === 2 || String(sev).toLowerCase() === 'high') return 'high';
    if (sev === 3 || String(sev).toLowerCase() === 'medium') return 'medium';
    return 'low';
  };
  if (Array.isArray(options.trafficAlerts)) {
    for (const a of options.trafficAlerts) {
      if (!a.srcIp && !a.destIp && !a.src_ip && !a.dest_ip ||
          a.srcIp === normalizedTarget || a.destIp === normalizedTarget ||
          a.src_ip === normalizedTarget || a.dest_ip === normalizedTarget ||
          a.target === normalizedTarget) {
        dossier.traffic.recentAlerts.push({ ...a, severity: normalizeTrafficSeverity(a.severity) });
      }
    }
  }
  const pcapDir = getVigilantePcapDir();
  if (fsSync.existsSync(pcapDir)) {
    try {
      const pcapFiles = await fs.readdir(pcapDir);
      for (const f of pcapFiles) {
        if (!f.endsWith('.json') && !f.endsWith('.jsonl') && !f.endsWith('.ndjson')) continue;
        try {
          const raw = await fs.readFile(path.join(pcapDir, f), 'utf8');
          const trimmed = raw.trim();
          if (trimmed.startsWith('{') && trimmed.endsWith('}') && !trimmed.includes('\n')) {
            const parsed = JSON.parse(trimmed);
            for (const a of parsed.alerts || parsed.recentAlerts || []) {
              if (a.srcIp === normalizedTarget || a.destIp === normalizedTarget ||
                  a.src_ip === normalizedTarget || a.dest_ip === normalizedTarget ||
                  parsed.target === normalizedTarget) {
                dossier.traffic.recentAlerts.push({ ...a, severity: normalizeTrafficSeverity(a.severity) });
              }
            }
          } else {
            const eve = parseSuricataEve(raw);
            for (const a of eve.alerts || []) {
              if (a.srcIp === normalizedTarget || a.destIp === normalizedTarget) {
                dossier.traffic.recentAlerts.push({ ...a, severity: normalizeTrafficSeverity(a.severity) });
              }
            }
          }
        } catch {
          // ignore corrupted traffic logs
        }
      }
    } catch {
      // ignore unreadable pcapDir
    }
  }
  dossier.traffic.alertCount = dossier.traffic.recentAlerts.length;

  // Deduplicate open ports & techniques
  dossier.network.openPorts = [...new Set(dossier.network.openPorts)].sort((a, b) => a - b);
  dossier.mitreTechniques = [...new Set(dossier.mitreTechniques)];
  dossier.remediations = [...new Set(dossier.remediations)];

  // Calculate composite risk (separate by source to prevent double-counting)
  const riskInputs = {
    nuclei: {
      critical: dossier.vulnerabilities.cves.filter(c => c.source === 'nuclei' && String(c.severity).toLowerCase() === 'critical').length,
      high: dossier.vulnerabilities.cves.filter(c => c.source === 'nuclei' && String(c.severity).toLowerCase() === 'high').length,
      medium: dossier.vulnerabilities.cves.filter(c => c.source === 'nuclei' && String(c.severity).toLowerCase() === 'medium').length
    },
    trivy: {
      critical: dossier.vulnerabilities.cves.filter(c => c.source === 'trivy' && String(c.severity).toUpperCase() === 'CRITICAL').length,
      high: dossier.vulnerabilities.cves.filter(c => c.source === 'trivy' && String(c.severity).toUpperCase() === 'HIGH').length,
      secrets: dossier.vulnerabilities.secrets.length
    },
    netexec: {
      signingDisabled: netexecSigningDisabled,
      guestAuthAllowed: netexecGuestAllowed,
      nullSession: netexecNullSession
    },
    oobscan: {
      isBmc: dossier.outOfBand.detected,
      rakpDumped: Boolean(dossier.outOfBand.details?.rakpHash)
    },
    zap: {
      high: dossier.vulnerabilities.zapAlerts.filter(a => a.risk === 'High').length,
      medium: dossier.vulnerabilities.zapAlerts.filter(a => a.risk === 'Medium').length
    },
    bloodhound: {
      tier0Compromised: bhTier0,
      compromised: bhCompromised
    },
    traffic: {
      criticalAlerts: dossier.traffic.recentAlerts.some(a => a.severity === 'critical'),
      highAlerts: dossier.traffic.recentAlerts.some(a => a.severity === 'high')
    }
  };

  const risk = calculateRiskScore(riskInputs);
  dossier.riskScore = risk.score;
  dossier.riskTier = risk.tier;
  dossier.riskColor = risk.color;

  // Persist dossier
  const dossierPath = resolvePathInside(dossiersDir, `${cleanTarget}.json`);
  await fs.writeFile(dossierPath, JSON.stringify(dossier, null, 2), 'utf8');

  try {
    await saveEvidenceFile('dossiers', cleanTarget, `${cleanTarget}.json`, JSON.stringify(dossier, null, 2));
    await autoSignIfConfigured(resolvePathInside(getHostEvidenceDir('dossiers', cleanTarget), `${cleanTarget}.json`));
  } catch (err) {
    logger.warn('DOSSIER', `Failed to save signed evidence: ${err.message}`);
  }

  logger.info('DOSSIER', `Compiled Unified Host Dossier for ${target} (Risk: ${risk.score}/100 [${risk.tier}])`);
  return dossier;
}

/**
 * Retrieve saved dossier for a target
 * @param {string} target
 * @returns {Promise<Object|null>}
 */
export async function getHostDossier(target) {
  await ensureVigilanteConfig();
  const dossiersDir = getVigilanteDossiersDir();
  const cleanTarget = sanitizePathComponent(target);
  const dossierPath = resolvePathInside(dossiersDir, `${cleanTarget}.json`);

  if (fsSync.existsSync(dossierPath)) {
    try {
      const raw = await fs.readFile(dossierPath, 'utf8');
      return JSON.parse(raw);
    } catch {
      // fallback
    }
  }

  return buildHostDossier(target);
}

/**
 * List all compiled Host Dossiers
 * @returns {Promise<Array<Object>>}
 */
export async function listHostDossiers() {
  await ensureVigilanteConfig();
  const dossiersDir = getVigilanteDossiersDir();

  try {
    const files = await fs.readdir(dossiersDir);
    const dossiers = [];
    for (const f of files) {
      if (f.endsWith('.json')) {
        try {
          const raw = await fs.readFile(path.join(dossiersDir, f), 'utf8');
          const data = JSON.parse(raw);
          dossiers.push({
            target: data.target,
            riskScore: data.riskScore || 0,
            riskTier: data.riskTier || 'CLEAN',
            riskColor: data.riskColor || 'green',
            openPortsCount: (data.network?.openPorts || []).length,
            cvesCount: (data.vulnerabilities?.cves || []).length,
            isBmc: Boolean(data.outOfBand?.detected),
            updatedAt: data.updatedAt
          });
        } catch {
          // ignore corrupted files
        }
      }
    }
    return dossiers.sort((a, b) => b.riskScore - a.riskScore);
  } catch (err) {
    logger.warn('DOSSIER', `Failed to list host dossiers: ${err.message}`);
    return [];
  }
}
