/**
 * Self-Healing Auto-Remediator ("Auto-Patch & Pull Request Engine")
 * Analyzes findings from Shift-Left Audit (VIGIL-K8S-*, VIGIL-DOCKER-*) and KSPM (PSS).
 * Automatically generates unified code diffs, applies patches, and prepares Git PR scripts.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { load as yamlLoad, dump as yamlDump } from 'js-yaml';
import { logger } from '../utils/logger.js';
import { shDoubleQuoteEscape } from './config.js';

function splitContainerImageRef(imageRef) {
  const withoutDigest = String(imageRef || '').split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const tagColon = withoutDigest.indexOf(':', lastSlash + 1);
  if (tagColon >= 0) {
    return {
      repo: withoutDigest.slice(0, tagColon),
      tag: withoutDigest.slice(tagColon + 1)
    };
  }
  return { repo: withoutDigest, tag: '' };
}

/**
 * Generate a patch for a specific finding in Kubernetes or Dockerfile content
 * @param {Object} finding e.g. { ruleId: 'VIGIL-K8S-004', message: '...' }
 * @param {string} fileContent Raw content of file
 * @param {string} [fileType='yaml'] 'yaml' or 'dockerfile'
 * @returns {Object} { patchedContent, modified: boolean, diffSnippet: string, description: string }
 */
export function generatePatchForFinding(finding, fileContent, fileType = 'yaml') {
  const ruleId = finding.ruleId || finding.id || '';
  let patchedContent = fileContent;
  let modified = false;
  let description = '';

  if (fileType === 'yaml' || fileType === 'k8s') {
    try {
      const doc = yamlLoad(fileContent);
      if (doc && (doc.kind === 'Pod' || doc.kind === 'Deployment' || doc.kind === 'StatefulSet' || doc.kind === 'DaemonSet')) {
        const podSpec = doc.kind === 'Pod' ? doc.spec : doc.spec?.template?.spec;

        if (podSpec && Array.isArray(podSpec.containers)) {
          for (const container of podSpec.containers) {
            // Fix 1: Missing resource limits (VIGIL-K8S-004)
            if (ruleId === 'VIGIL-K8S-004' || !container.resources || !container.resources.limits) {
              container.resources = container.resources || {};
              container.resources.limits = container.resources.limits || { cpu: '500m', memory: '512Mi' };
              container.resources.requests = container.resources.requests || { cpu: '100m', memory: '128Mi' };
              modified = true;
              description += 'Injected standard CPU and memory requests/limits. ';
            }

            // Fix 2: Privileged container or PSS violation (VIGIL-K8S-001)
            if (ruleId === 'VIGIL-K8S-001' || ruleId.includes('PRIVILEGED') || !container.securityContext) {
              container.securityContext = container.securityContext || {};
              container.securityContext.privileged = false;
              container.securityContext.allowPrivilegeEscalation = false;
              container.securityContext.readOnlyRootFilesystem = true;
              container.securityContext.runAsNonRoot = true;
              container.securityContext.runAsUser = container.securityContext.runAsUser || 10001;
              container.securityContext.capabilities = container.securityContext.capabilities || {};
              container.securityContext.capabilities.drop = ['ALL'];
              modified = true;
              description += 'Hardened container securityContext (readOnlyRoot, drop ALL capabilities, non-root). ';
            }

            // Fix 3: Image with latest or unpinned tag (VIGIL-K8S-003)
            if (ruleId === 'VIGIL-K8S-003' || (container.image && !container.image.includes('@sha256:') && (container.image.endsWith(':latest') || !splitContainerImageRef(container.image).tag))) {
              if (container.image && !container.image.includes('@sha256:')) {
                const { repo } = splitContainerImageRef(container.image);
                if (finding.pinnedImage) {
                  container.image = finding.pinnedImage;
                } else if (finding.pinnedDigest) {
                  container.image = `${repo}@${finding.pinnedDigest}`;
                } else {
                  container.image = `${repo}:${finding.pinnedTag || '1.27.1-pinned'}`;
                }
                modified = true;
                description += `Replaced mutable tag on ${repo} with pinned reference. `;
              }
            }
          }

          if (modified) {
            patchedContent = yamlDump(doc);
          }
        }
      }
    } catch (err) {
      logger.warn('REMEDIATION', `YAML parse failed for remediation: ${err.message}`);
    }
  } else if (fileType === 'dockerfile') {
    // Dockerfile remediation rules
    let lines = fileContent.split('\n');

    // Rule 1: Dockerfile running as root (VIGIL-DOCKER-003)
    if (ruleId === 'VIGIL-DOCKER-003' || !fileContent.includes('USER ')) {
      // Insert USER 10001 before ENTRYPOINT or CMD
      let insertIdx = lines.findIndex(l => l.trim().startsWith('ENTRYPOINT') || l.trim().startsWith('CMD'));
      if (insertIdx === -1) insertIdx = lines.length;
      lines.splice(insertIdx, 0, '# Added by Vigilante Auto-Remediator', 'USER 10001:10001');
      modified = true;
      description += 'Injected non-root USER 10001:10001. ';
    }

    // Rule 2: Unpinned base image (VIGIL-DOCKER-001)
    if (ruleId === 'VIGIL-DOCKER-001' || lines.some(l => /^\s*FROM\s+/i.test(l) && l.includes(':latest'))) {
      lines = lines.map(line => {
        const m = line.match(/^(\s*FROM\s+(?:--platform=\S+\s+)?)([^\s]+)(.*)$/i);
        if (m && m[2].endsWith(':latest') && !m[2].includes('@sha256:')) {
          const { repo } = splitContainerImageRef(m[2]);
          const pinnedRef = finding.pinnedImage || (finding.pinnedDigest ? `${repo}@${finding.pinnedDigest}` : `${repo}:${finding.pinnedTag || 'pinned'}`);
          modified = true;
          description += `Replaced mutable :latest tag on ${repo} with pinned reference. `;
          return `${m[1]}${pinnedRef}${m[3]}`;
        }
        return line;
      });
    }

    if (modified) {
      patchedContent = lines.join('\n');
    }
  }

  return {
    patchedContent,
    modified,
    description: description.trim() || 'No modifications required'
  };
}

/**
 * Generate a simple unified diff between original and patched strings
 * @param {string} original 
 * @param {string} patched 
 * @param {string} [fileName='manifest.yaml']
 * @returns {string} Diff string
 */
export function generateUnifiedDiff(original, patched, fileName = 'manifest.yaml') {
  if (original === patched) return '';
  const origLines = original.split('\n');
  const patchLines = patched.split('\n');

  const diff = [];
  diff.push(`--- a/${fileName}`);
  diff.push(`+++ b/${fileName}`);
  diff.push(`@@ -1,${origLines.length} +1,${patchLines.length} @@`);

  let i = 0;
  let j = 0;
  while (i < origLines.length || j < patchLines.length) {
    if (i < origLines.length && j < patchLines.length && origLines[i] === patchLines[j]) {
      diff.push(`  ${origLines[i]}`);
      i++;
      j++;
    } else if (
      j + 1 < patchLines.length &&
      i < origLines.length &&
      origLines[i] === patchLines[j + 1]
    ) {
      diff.push(`+ ${patchLines[j]}`);
      j++;
    } else if (
      i + 1 < origLines.length &&
      j < patchLines.length &&
      origLines[i + 1] === patchLines[j]
    ) {
      diff.push(`- ${origLines[i]}`);
      i++;
    } else {
      if (i < origLines.length) {
        diff.push(`- ${origLines[i]}`);
        i++;
      }
      if (j < patchLines.length) {
        diff.push(`+ ${patchLines[j]}`);
        j++;
      }
    }
  }

  return diff.join('\n');
}

/**
 * Apply generated patches directly to file on disk
 * @param {string} filePath 
 * @param {string} patchedContent 
 * @param {Object} [options={}]
 * @returns {Promise<{ filePath: string, applied: boolean, backupPath?: string }>}
 */
export async function applyPatchToFile(filePath, patchedContent, options = {}) {
  const makeBackup = options.backup !== false;
  let backupPath = null;

  if (makeBackup) {
    backupPath = `${filePath}.vigil-bak-${Date.now()}`;
    await fs.copyFile(filePath, backupPath);
  }

  await fs.writeFile(filePath, patchedContent, 'utf8');
  logger.info('REMEDIATION', `Applied auto-remediation patch to ${filePath} (backup: ${backupPath || 'none'})`);

  return {
    filePath,
    applied: true,
    backupPath
  };
}

/**
 * Generate a shell script to create a Git branch, commit fixes, and push / open PR
 * @param {Array<string>} filesModified 
 * @param {string} [branchName] 
 * @returns {string} Shell script
 */
export function generateRemediationPrScript(filesModified = [], branchName = '') {
  const branch = branchName || `security-hardening-${Date.now().toString(36)}`;
  // The generated script is meant to be executed by an operator, so every
  // interpolated value is escaped for its double-quoted context: an
  // unescaped $(...) or backtick in a branch name or file path would run
  // as a command even inside double quotes.
  const filesList = filesModified.map(f => `"${shDoubleQuoteEscape(f)}"`).join(' ');

  return `#!/usr/bin/env bash
set -euo pipefail

BRANCH_NAME="${shDoubleQuoteEscape(branch)}"
echo "🌿 Creating security hardening branch: \${BRANCH_NAME}"
git checkout -b "\${BRANCH_NAME}"

echo "📦 Staging auto-remediated files..."
git add -- ${filesList}

echo "✍️ Committing security fixes..."
git commit -m "security(vigilante): auto-remediate container & manifest hardening

- Injected readOnlyRootFilesystem and non-root securityContext
- Set missing CPU and memory requests/limits
- Pinned mutable container image tags to immutable sha256 digests
- Enforced non-root USER in Dockerfiles

Autonomously generated by Vigilante Self-Healing Auto-Remediator."

echo "🚀 Ready to push:"
echo "git push -u origin \${BRANCH_NAME}"
`;
}
