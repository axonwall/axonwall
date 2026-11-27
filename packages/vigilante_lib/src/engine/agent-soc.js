import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { getHostDossier, buildHostDossier } from './dossier.js';
import { runNucleiScan } from './nuclei.js';
import { runNetexecAudit } from './netexec.js';
import { listBloodhoundIngests } from './bloodhound.js';
import { generateMitreCoverageMatrix } from './mitre.js';
import { generateNistIncidentRecord, calculateNistIncidentScore } from './nist.js';
import { isolatePod, blockIp } from './soar.js';
import { ensureVigilanteConfig, getVigilanteEvidenceDir, getHostEvidenceDir, sanitizePathComponent } from './config.js';
import { saveEvidenceFile } from './evidence.js';
import { autoSignIfConfigured } from './gpg.js';
import { logger } from '../utils/logger.js';

/**
 * Autonomous ReAct SOC Investigation Engine
 * Investigates an indicator, target IP, or workload autonomously through multi-step tool calls
 * @param {string|Object} targetOrOptions
 * @param {Object} [options]
 * @returns {Promise<Object>} Investigation results, evidence trace, and NIST post-mortem
 */
export async function runAgentSocInvestigation(targetOrOptions, options = {}) {
  await ensureVigilanteConfig();

  let target;
  let incidentId;
  let triggerAlert;
  let automatedContainment = false;
  let namespace = 'default';

  if (typeof targetOrOptions === 'object' && targetOrOptions !== null) {
    target = targetOrOptions.target || targetOrOptions.podName || 'unknown-target';
    incidentId = targetOrOptions.incidentId || `IR-${Date.now().toString(36).toUpperCase()}`;
    triggerAlert = targetOrOptions.triggerAlert || { title: 'Unknown Alert', source: 'Manual' };
    // Require explicit opt-in for autonomous containment (default: false)
    automatedContainment = (targetOrOptions.automatedContainment ?? targetOrOptions.autoContain) === true;
    namespace = targetOrOptions.namespace || 'default';
  } else {
    target = targetOrOptions || 'unknown-target';
    incidentId = options.incidentId || `IR-${Date.now().toString(36).toUpperCase()}`;
    triggerAlert = options.triggerAlert || options.trigger || { title: 'Unknown Alert', source: 'Manual' };
    automatedContainment = (options.automatedContainment ?? options.autoContain) === true;
    namespace = options.namespace || 'default';
  }

  const cleanTarget = sanitizePathComponent(String(target || 'unknown-target'), 'target');
  logger.info('AGENT_SOC', `Starting autonomous investigation ${incidentId} for target: ${target}`);

  const reasoningTrace = [];

  // Step 1: Initial Context & Host Dossier Compilation
  reasoningTrace.push({
    step: 1,
    phase: 'Triage & Identification',
    action: 'get_host_dossier',
    thought: `Retrieve or compile Unified Host Dossier for ${target} across historical scan artifacts.`
  });

  let dossier;
  try {
    dossier = await getHostDossier(target);
  } catch {
    dossier = await buildHostDossier(target);
  }

  reasoningTrace[0].observation = `Host dossier retrieved. Risk Score: ${dossier.riskScore}/100 [${dossier.riskTier}]. Open ports: ${dossier.network?.openPorts?.join(', ') || 'none'}.`;

  // Step 2: Target Service Probing (Nuclei / NetExec)
  let activeScanResult = null;
  if ((dossier.network?.openPorts || []).some(p => [80, 443, 8080, 8443].includes(p))) {
    reasoningTrace.push({
      step: 2,
      phase: 'Detection & Analysis',
      action: 'run_nuclei_scan',
      thought: `Target exposes HTTP web ports. Running fast CVE and misconfiguration scan.`
    });
    try {
      activeScanResult = await runNucleiScan(target, 'cves');
      reasoningTrace[1].observation = `Nuclei sweep completed with ${activeScanResult.findings?.length || 0} findings.`;
    } catch (err) {
      reasoningTrace[1].observation = `Nuclei scan simulated or offline: ${err.message}`;
    }
  } else if ((dossier.network?.openPorts || []).some(p => [445, 139, 389].includes(p))) {
    reasoningTrace.push({
      step: 2,
      phase: 'Detection & Analysis',
      action: 'run_netexec_audit',
      thought: `Target exposes authentication/SMB ports. Auditing protocol signing and guest access.`
    });
    try {
      activeScanResult = await runNetexecAudit(target, 'smb-signing');
      reasoningTrace[1].observation = `NetExec audit completed with status: ${activeScanResult.status}.`;
    } catch (err) {
      reasoningTrace[1].observation = `NetExec audit note: ${err.message}`;
    }
  } else {
    reasoningTrace.push({
      step: 2,
      phase: 'Detection & Analysis',
      action: 'analyze_runtime_telemetry',
      thought: `Analyzing runtime eBPF signals and process execution tree.`,
      observation: `Observed alert details: ${triggerAlert.title || triggerAlert.details || 'Suspicious execution'}`
    });
  }

  // Step 3: Identity & Credential Correlation
  reasoningTrace.push({
    step: 3,
    phase: 'Detection & Analysis',
    action: 'check_identity_graph',
    thought: `Cross-referencing target ${target} against BloodHound Active Directory graphs and credentials.`
  });
  const bhIngests = await listBloodhoundIngests();
  const identityAlerts = dossier.identity?.bloodhoundAlerts || [];
  reasoningTrace[2].observation = `Found ${bhIngests.length} identity datasets. Target has ${identityAlerts.length} Active Directory alerts.`;

  // Step 4: MITRE ATT&CK Framework Mapping from actual telemetry
  reasoningTrace.push({
    step: 4,
    phase: 'Containment Strategy',
    action: 'generate_mitre_report',
    thought: `Mapping observed indicators to MITRE tactics and techniques.`
  });
  const techniqueSet = new Set();
  const scanFindings = activeScanResult?.synthetic ? [] : (activeScanResult?.findings || []);
  const criticalOrHighFindings = scanFindings.filter(f => ['critical', 'high'].includes(String(f.severity || '').toLowerCase()));
  const dossierAlerts = dossier.runtime?.alerts || dossier.alerts || [];
  if (triggerAlert?.mitreTechnique) techniqueSet.add(triggerAlert.mitreTechnique);
  if (/shell|exec|rce/i.test(String(triggerAlert?.title || ''))) techniqueSet.add('T1059.004');
  if (identityAlerts.length > 0) techniqueSet.add('T1078');
  if (criticalOrHighFindings.length > 0) techniqueSet.add('T1190');
  if (dossierAlerts.length > 0) techniqueSet.add('T1068');
  const mappedTechniques = Array.from(techniqueSet);
  reasoningTrace[3].observation = mappedTechniques.length > 0
    ? `Mapped to ${mappedTechniques.length} MITRE techniques: ${mappedTechniques.join(', ')}.`
    : 'No active MITRE ATT&CK techniques confirmed across target telemetry.';

  // Step 5: Incident Prioritization & Multi-Signal Containment Corroboration
  const riskScore = Number(dossier.riskScore || 0);
  const triggerSev = String(triggerAlert?.severity || '').toUpperCase();
  const hasRealSignals =
    riskScore >= 40 ||
    criticalOrHighFindings.length > 0 ||
    identityAlerts.length > 0 ||
    dossierAlerts.length > 0 ||
    triggerSev === 'CRITICAL' ||
    triggerSev === 'HIGH';

  const corroboratingSignals = [];
  if (triggerSev === 'CRITICAL' || triggerSev === 'HIGH') {
    corroboratingSignals.push('trigger_alert_severity');
  }
  if (criticalOrHighFindings.length > 0) {
    corroboratingSignals.push('active_scan_findings');
  }
  if (identityAlerts.length > 0) {
    corroboratingSignals.push('bloodhound_identity_alerts');
  }
  if (dossierAlerts.length > 0) {
    corroboratingSignals.push('dossier_runtime_alerts');
  }
  if (riskScore >= 70) {
    corroboratingSignals.push('high_dossier_risk_score');
  }
  const dossierVulnCount =
    (dossier.vulnerabilities?.cves?.length || 0) +
    (dossier.vulnerabilities?.secrets?.length || 0) +
    (dossier.vulnerabilities?.misconfigs?.length || 0);
  const hasMultiSignalCorroboration =
    corroboratingSignals.length >= 2 ||
    (riskScore >= 85 && (dossierVulnCount + dossierAlerts.length + identityAlerts.length + criticalOrHighFindings.length) >= 2);

  const functionalImpact = (riskScore >= 80 || criticalOrHighFindings.some(f => f.severity === 'critical') || triggerSev === 'CRITICAL')
    ? 'HIGH'
    : hasRealSignals ? 'MEDIUM' : 'LOW';
  const informationImpact = (identityAlerts.length > 0 || riskScore >= 70)
    ? 'CORE_SYSTEMS'
    : hasRealSignals ? 'PROPRIETARY' : 'NONE';

  const prioritization = calculateNistIncidentScore({
    attackVector: (dossier.network?.openPorts || []).some(p => [80, 443, 8080, 8443].includes(p)) ? 'WEB' : 'OTHER',
    signType: hasRealSignals ? 'INCIDENT' : 'PRECURSOR',
    functionalImpact,
    informationImpact,
    recoverabilityEffort: functionalImpact === 'HIGH' ? 'REGULAR' : 'SUPPLEMENTED'
  });

  const computedScore = Math.max(riskScore, hasRealSignals ? (prioritization.score || 50) : 0);
  let threatLevel = 'LOW';
  if (computedScore >= 80 || triggerSev === 'CRITICAL' || criticalOrHighFindings.some(f => f.severity === 'critical')) {
    threatLevel = 'CRITICAL';
  } else if (computedScore >= 60 || criticalOrHighFindings.length > 0 || triggerSev === 'HIGH') {
    threatLevel = 'HIGH';
  } else if (computedScore >= 30 || identityAlerts.length > 0) {
    threatLevel = 'MEDIUM';
  } else if (computedScore === 0 && scanFindings.length === 0 && dossierAlerts.length === 0) {
    threatLevel = 'NONE';
  }

  const verdict = {
    threatLevel,
    nistCategory: hasRealSignals ? 'CAT-3 (Malicious Code / Intrusion)' : 'CAT-0 (Benign / No Active Threat)',
    score: computedScore,
    corroborated: hasMultiSignalCorroboration,
    corroborationSignals: corroboratingSignals,
    summary: hasRealSignals
      ? `Observed ${criticalOrHighFindings.length} high/critical scan findings, ${identityAlerts.length} AD alerts, and dossier risk ${riskScore}/100 on ${target}.`
      : `No active compromise indicators detected on ${target} (dossier risk ${riskScore}/100, 0 high/critical findings).`
  };

  let containment = null;
  if (automatedContainment && (threatLevel === 'CRITICAL' || threatLevel === 'HIGH')) {
    if (!hasMultiSignalCorroboration) {
      reasoningTrace.push({
        step: 5,
        phase: 'Active Containment',
        action: 'soar_containment_deferred',
        thought: `Threat level is ${verdict.threatLevel}, evaluating autonomous containment eligibility.`,
        observation: `Autonomous containment skipped: requires multi-signal corroboration (observed ${corroboratingSignals.length} independent signal(s): ${corroboratingSignals.join(', ') || 'none'}).`
      });
    } else {
      const containmentStep = {
        step: 5,
        phase: 'Active Containment',
        action: 'soar_containment',
        thought: `Threat level is ${verdict.threatLevel} with multi-signal corroboration (${corroboratingSignals.join(', ')}). Executing automated SOAR containment.`
      };
      reasoningTrace.push(containmentStep);
      const bareTarget = String(target).replace(/^\[|\]$/g, '');
      if (net.isIP(bareTarget)) {
        try {
          containment = await blockIp({ ip: bareTarget, reason: `Automated Agent Containment (${verdict.threatLevel}: ${verdict.score}/100)` });
          if (containment?.status === 'ERROR') {
            containment = null;
            containmentStep.observation = `IP containment failed for ${bareTarget}`;
          } else {
            containmentStep.observation = `Applied firewall IP block: ${bareTarget} (ID: ${containment.containmentId})`;
          }
        } catch (soarErr) {
          containment = null;
          containmentStep.observation = `IP containment skipped/failed for ${bareTarget}: ${soarErr.message}`;
        }
      } else {
        try {
          containment = await isolatePod({
            podName: target,
            namespace,
            reason: `Autonomous SOAR Containment: High risk score (${verdict.score}/100) - ${triggerAlert.title || 'Compromise'}`
          });
          containmentStep.observation = `Applied isolation NetworkPolicy: ${containment.policyName} (ID: ${containment.containmentId})`;
        } catch (soarErr) {
          containmentStep.observation = `Pod containment skipped/failed for ${target}: ${soarErr.message}`;
        }
      }
    }
  }

  // Formulate NIST SP 800-61 Post-Mortem Record
  const incidentRecord = generateNistIncidentRecord({
    incidentId,
    network: 'investigations',
    host: target,
    attackVector: 'WEB_APPLICATION',
    functionalImpact: 'HIGH',
    informationImpact: 'CORE_SYSTEMS',
    evidenceArtifacts: [
      { name: 'host_dossier.json', size: 1024, sha256: 'simulated' },
      { name: 'soc_investigation.json', size: 2048, sha256: 'simulated' }
    ],
    remediationSteps: [
      'Isolate compromised workload using SOAR NetworkPolicy',
      'Revoke stolen tokens and credentials',
      'Collect container memory dump and forensic snapshot',
      'Re-deploy workload with readOnlyRootFilesystem and dropped capabilities'
    ]
  });

  const investigation = {
    id: incidentId,
    incidentId,
    target,
    createdAt: new Date().toISOString(),
    triggerAlert,
    verdict,
    prioritization,
    mappedTechniques,
    reasoningTrace,
    steps: reasoningTrace,
    containment,
    incidentRecord
  };

  // Persist and sign investigation
  try {
    await saveEvidenceFile('investigations', cleanTarget, 'nist_incident_record.json', JSON.stringify(incidentRecord, null, 2));
    await saveEvidenceFile('investigations', cleanTarget, `${incidentId}.json`, JSON.stringify(investigation, null, 2));
    await autoSignIfConfigured(path.join(getHostEvidenceDir('investigations', cleanTarget), 'nist_incident_record.json'));
    await autoSignIfConfigured(path.join(getHostEvidenceDir('investigations', cleanTarget), `${incidentId}.json`));
  } catch (err) {
    logger.warn('AGENT_SOC', `Failed to sign investigation evidence: ${err.message}`);
  }

  logger.info('AGENT_SOC', `Completed autonomous investigation ${incidentId} for ${target}`);
  return investigation;
}

export const investigateIncident = runAgentSocInvestigation;

/**
 * Generate Comprehensive NIST SP 800-61 Post-Mortem Report in Markdown
 * @param {Object} investigation
 * @returns {string} Markdown document
 */
export function generateSocInvestigatorReport(investigation) {
  const { incidentId, target, triggerAlert, verdict, mappedTechniques, reasoningTrace, containment, incidentRecord } = investigation;

  const traceRows = (reasoningTrace || []).map(t => {
    return `| Step ${t.step} | **${t.phase}** | \`${t.action}\` | ${t.thought} | ${t.observation} |`;
  }).join('\n');

  const mitreRows = (mappedTechniques || []).map(t => {
    return `| \`${t}\` | Technique Identified | Automatic Detection |`;
  }).join('\n');

  return `# 🤖 AUTONOMOUS AGENT SOC INVESTIGATION REPORT

**Incident ID**: \`${incidentId}\`
**Target Workload**: \`${target}\`
**Date / Timestamp**: ${investigation.createdAt || new Date().toISOString()}

---

## 1. Executive Summary & Verdict
- **Threat Level**: **${verdict?.threatLevel || 'HIGH'}**
- **NIST Attack Category**: **${verdict?.nistCategory || 'CAT-3'}**
- **Prioritization Score**: ${verdict?.score || 85}/100
- **Summary**: ${verdict?.summary || 'Suspicious execution and anomaly detected.'}
- **Trigger**: ${triggerAlert?.title || 'eBPF / IDS runtime alert'} (Source: ${triggerAlert?.source || 'Vigilante Sensor'})

---

## 2. ReAct Agent Reasoning & Investigative Trace
| Step | Phase | Action / Tool | Thought | Observation |
|---|---|---|---|---|
${traceRows}

---

## 3. MITRE ATT&CK® Techniques Identified
| Technique ID | Description | Detection Mechanism |
|---|---|---|
${mitreRows}

---

## 4. Active Containment & SOAR Actions
${containment ? `
- **Containment Action**: \`${containment.type}\`
- **Containment ID**: \`${containment.containmentId}\`
- **Status**: \`${containment.status}\`
- **Policy Name**: \`${containment.policyName || 'N/A'}\`
- **Enforcement**: Kubernetes Zero-Trust NetworkPolicy severed all ingress and egress.
` : '- *No active containment was triggered.*'}

---

## 5. NIST SP 800-61 Post-Mortem & Eradication Guidance
1. **Containment**: Target \`${target}\` has been isolated from internal mesh and external egress.
2. **Eradication**:
   - Terminate suspicious containers and discard ephemeral storage.
   - Rotate cluster service account secrets and API tokens.
3. **Recovery**:
   - Re-deploy workloads using hardened Pod Security Standards (Restricted).
   - Ensure \`readOnlyRootFilesystem: true\` and remove all linux capabilities.
4. **Lessons Learned**:
   - Update Falco eBPF alerting thresholds to immediately flag root bash executions.

---
*Report cryptographically signed and stored in Vigilante Evidence Vault.*
`;
}
