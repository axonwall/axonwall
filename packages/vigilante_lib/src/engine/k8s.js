import fsSync from 'node:fs';
import crypto from 'node:crypto';
import { execa } from 'execa';
import { logger } from '../utils/logger.js';
import { isValidDnsLabel } from './config.js';

/**
 * Resolve execution environment for kubectl / helm so the in-house K3s
 * kubeconfig (/etc/rancher/k3s/k3s.yaml) is automatically used when present.
 * @returns {NodeJS.ProcessEnv}
 */
export function getKubeExecutionEnv() {
  if (!process.env.KUBECONFIG) {
    try {
      if (fsSync.existsSync('/etc/rancher/k3s/k3s.yaml')) {
        return {
          ...process.env,
          KUBECONFIG: '/etc/rancher/k3s/k3s.yaml',
        };
      }
    } catch {
      // Ignore fs check error
    }
  }
  return process.env;
}

/**
 * Apply Kubernetes manifest YAML with validation fallback and transient error retries
 * @param {string} yamlContent - YAML string to apply via stdin
 * @param {Object} [options] - Options
 * @param {number} [options.maxRetries=6] - Maximum retry attempts
 * @param {number} [options.retryDelayMs=1000] - Base delay between retries
 * @param {Function} [options.onLog] - Log callback
 * @returns {Promise<string>} - kubectl stdout
 */
export async function safeKubectlApply(yamlContent, options = {}) {
  const { maxRetries = 6, retryDelayMs = 1000, onLog = null } = options;

  let lastError;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const { stdout } = await execa('kubectl', [
        'apply',
        '--validate=false',
        '-f', '-'
      ], {
        input: yamlContent,
        env: getKubeExecutionEnv()
      });
      return stdout;
    } catch (err) {
      lastError = err;
      const msg = err.message || '';
      const isTransient = msg.includes('failed to download openapi') ||
                          msg.includes('unable to handle the request') ||
                          msg.includes('connection refused') ||
                          msg.includes('i/o timeout') ||
                          msg.includes('EOF') ||
                          msg.includes('503 Service Unavailable');

      if (isTransient && attempt < maxRetries) {
        const waitMs = retryDelayMs * attempt;
        logger.warn('K8S:APPLY_RETRY', `Kubernetes API server transient error (attempt ${attempt}/${maxRetries}): ${msg}. Retrying in ${waitMs}ms...`);
        if (onLog) {
          onLog(`Kubernetes API server warming up (attempt ${attempt}/${maxRetries}). Retrying apply in ${(waitMs / 1000).toFixed(1)}s...`);
        }
        await new Promise((r) => setTimeout(r, waitMs));
      } else {
        throw err;
      }
    }
  }

  throw lastError;
}

/**
 * Ensure target Kubernetes namespace exists safely
 * @param {string} namespace - Target namespace name
 * @param {Object} [options] - Options
 */
export async function ensureNamespace(namespace = 'default', options = {}) {
  if (!namespace || namespace === 'default') {
    return;
  }

  // A namespace is a DNS label: reject names kubectl would refuse (or
  // that arrived unsanitized from UI input) with a clear error instead
  // of passing them verbatim to kubectl create.
  if (!isValidDnsLabel(namespace)) {
    throw new Error(`Invalid namespace '${namespace}': expected a DNS label (lowercase alphanumerics and '-', 1-63 chars, starting and ending with an alphanumeric).`);
  }

  const { onLog = null } = options;
  const kubeEnv = getKubeExecutionEnv();

  try {
    // Check if namespace already exists
    await execa('kubectl', ['get', 'namespace', namespace, '--request-timeout=5s'], { env: kubeEnv });
    return;
  } catch {
    // Namespace does not exist or API call failed; attempt creation
  }

  try {
    await execa('kubectl', ['create', 'namespace', namespace], { env: kubeEnv });
    if (onLog) onLog(`✔ Created Kubernetes namespace '${namespace}'.`);
  } catch (createErr) {
    const errMsg = createErr.message || '';
    if (errMsg.includes('AlreadyExists') || createErr.stderr?.includes('AlreadyExists')) {
      return;
    }

    // Fallback: apply via dry-run YAML with retries and --validate=false
    try {
      const { stdout } = await execa('kubectl', [
        'create', 'namespace', namespace,
        '--dry-run=client', '-o', 'yaml'
      ], { env: kubeEnv });
      await safeKubectlApply(stdout, options);
    } catch (finalErr) {
      if (!finalErr.message?.includes('AlreadyExists')) {
        throw finalErr;
      }
    }
  }
}

/**
 * Wait for Kubernetes API server to be fully ready and responsive
 * @param {string} [clusterName='axonwall-k3s']
 * @param {number} [timeoutMs=60000]
 * @param {Function} [onLog]
 */
export async function waitForApiServerReady(clusterName = 'axonwall-k3s', timeoutMs = 60000, onLog = null) {
  const startTime = Date.now();
  const kubeEnv = getKubeExecutionEnv();
  logger.info('K8S:WAIT_READY', `Waiting for Kubernetes API server '${clusterName}' to become ready...`);

  while (Date.now() - startTime < timeoutMs) {
    try {
      const { stdout } = await execa('kubectl', [
        'get', '--raw', '/readyz',
        '--request-timeout=3s'
      ], { env: kubeEnv });
      if (stdout && stdout.trim() === 'ok') {
        logger.info('K8S:READY', `Kubernetes API server '${clusterName}' /readyz returned ok.`);
        return true;
      }
    } catch {
      // API server not ready yet
    }

    try {
      const { stdout } = await execa('kubectl', [
        'get', 'namespaces',
        '--request-timeout=3s'
      ], { env: kubeEnv });
      if (stdout && stdout.includes('default')) {
        logger.info('K8S:READY', `Kubernetes API server '${clusterName}' listed namespaces successfully.`);
        return true;
      }
    } catch {
      // Still warming up
    }

    await new Promise((r) => setTimeout(r, 1500));
  }

  return false;
}

/**
 * Resolve kubectl context arguments dynamically for k3s and k3d
 * @param {string} [clusterName='axonwall-k3s']
 * @param {string} [provider=null]
 * @returns {Promise<string[]>}
 */
export async function getClusterContextArgs(clusterName = 'axonwall-k3s', provider = null) {
  try {
    const { stdout } = await execa('kubectl', ['config', 'get-contexts', '-o', 'name'], { env: getKubeExecutionEnv() });
    const contexts = stdout.split('\n').map(c => c.trim()).filter(Boolean);

    if (provider === 'k3s') {
      if (contexts.includes(`k3s-${clusterName}`)) return ['--context', `k3s-${clusterName}`];
      if (contexts.includes('k3s')) return ['--context', 'k3s'];
      if (contexts.includes('default')) return ['--context', 'default'];
      return [];
    }

    if (provider === 'k3d' && contexts.includes(`k3d-${clusterName}`)) {
      return ['--context', `k3d-${clusterName}`];
    }

    if (contexts.includes(`k3d-${clusterName}`)) return ['--context', `k3d-${clusterName}`];
    if (contexts.includes(`k3s-${clusterName}`)) return ['--context', `k3s-${clusterName}`];
    if (contexts.includes('k3s')) return ['--context', 'k3s'];
    if (contexts.includes('default')) return ['--context', 'default'];
    return [];
  } catch {
    return [];
  }
}

/**
 * Resolve helm context arguments dynamically for k3s and k3d
 * @param {string} [clusterName='axonwall-k3s']
 * @param {string} [provider=null]
 * @returns {Promise<string[]>}
 */
export async function getHelmContextArgs(clusterName = 'axonwall-k3s', provider = null) {
  const ctxArgs = await getClusterContextArgs(clusterName, provider);
  if (ctxArgs.length === 2 && ctxArgs[0] === '--context') {
    return ['--kube-context', ctxArgs[1]];
  }
  return [];
}

/**
 * Generate a URL-safe high-entropy secret string for Kubernetes workloads.
 */
export function generateStrongSecret({ requireComplex = false } = {}) {
  const token = crypto.randomBytes(24).toString('base64url');
  return requireComplex ? `Ax9!${token}` : token;
}

/**
 * Ensure a Kubernetes Secret exists in the target namespace with the given keys,
 * reusing any already-populated secret values on upgrades so DB/app credentials
 * remain stable without shipping static passwords in repository manifests.
 *
 * @param {Object} params
 * @param {string} params.namespace
 * @param {string} params.secretName
 * @param {string[]|Record<string, string|Function>} params.keys
 * @param {string} [params.clusterName]
 * @param {string} [params.clusterProvider]
 * @returns {Promise<Record<string, string>>}
 */
export async function ensureGeneratedK8sSecret({
  namespace = 'default',
  secretName,
  keys = [],
  clusterName = null,
  clusterProvider = null
}) {
  if (!secretName || !isValidDnsLabel(secretName)) {
    throw new Error(`Invalid Kubernetes secret name '${secretName}'`);
  }
  if (namespace && namespace !== 'default' && !isValidDnsLabel(namespace)) {
    throw new Error(`Invalid Kubernetes namespace '${namespace}'`);
  }

  const kubeEnv = getKubeExecutionEnv();
  const ctxArgs = clusterName ? await getClusterContextArgs(clusterName, clusterProvider) : [];
  const existingData = {};

  try {
    const { stdout } = await execa(
      'kubectl',
      [...ctxArgs, 'get', 'secret', secretName, '-n', namespace, '-o', 'json'],
      { env: kubeEnv }
    );
    const parsed = JSON.parse(stdout || '{}');
    for (const [k, b64] of Object.entries(parsed?.data || {})) {
      if (typeof b64 === 'string') {
        existingData[k] = Buffer.from(b64, 'base64').toString('utf8');
      }
    }
  } catch {
    // Secret does not exist yet
  }

  const keyEntries = Array.isArray(keys) ? keys.map(k => [k, null]) : Object.entries(keys || {});
  const resolved = { ...existingData };
  let needsWrite = Object.keys(existingData).length === 0;

  for (const [key, valueOrFn] of keyEntries) {
    if (resolved[key]) continue;
    needsWrite = true;
    resolved[key] = typeof valueOrFn === 'function'
      ? valueOrFn(resolved)
      : (typeof valueOrFn === 'string' && valueOrFn.length > 0 ? valueOrFn : generateStrongSecret());
  }

  if (needsWrite) {
    const manifest = {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: secretName,
        namespace,
        labels: {
          'app.kubernetes.io/managed-by': 'vigilante'
        }
      },
      type: 'Opaque',
      stringData: resolved
    };
    await execa(
      'kubectl',
      [...ctxArgs, 'apply', '-f', '-'],
      {
        input: JSON.stringify(manifest),
        env: kubeEnv
      }
    );
  }

  return resolved;
}
