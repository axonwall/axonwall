import { execa } from 'execa';
import { spawnSync } from 'node:child_process';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { logger } from '../utils/logger.js';
import { runInteractiveTerminal } from '../utils/terminal-runner.js';
import { sanitizePathComponent, assertDnsLabel, assertCliTarget } from './config.js';
import { getClusterContextArgs, getKubeExecutionEnv } from './k8s.js';

function getSyncClusterContextArgs(clusterName) {
  if (!clusterName) return [];
  const clean = assertDnsLabel(clusterName, 'clusterName');
  try {
    const res = spawnSync('kubectl', ['config', 'get-contexts', '-o', 'name'], {
      encoding: 'utf8',
      env: getKubeExecutionEnv()
    });
    const contexts = String(res.stdout || '').split('\n').map(c => c.trim()).filter(Boolean);
    if (contexts.includes(`k3d-${clean}`)) return ['--context', `k3d-${clean}`];
    if (contexts.includes(`k3s-${clean}`)) return ['--context', `k3s-${clean}`];
    if (contexts.includes('k3s')) return ['--context', 'k3s'];
    if (contexts.includes('default')) return ['--context', 'default'];
  } catch {
    // Ignore context discovery failure
  }
  return [];
}

function assertContainerName(container) {
  const clean = assertCliTarget(container, 'container');
  if (/[./\\]/.test(clean)) {
    throw new Error(`Invalid container '${container}': must not contain path separators or dots`);
  }
  return clean;
}

/**
 * Format age from ISO timestamp into concise human string (e.g. 12s, 4m, 2h, 5d)
 * @param {string} timestamp
 * @returns {string}
 */
export function formatAge(timestamp) {
  if (!timestamp) return '<unknown>';
  const diffMs = Date.now() - new Date(timestamp).getTime();
  if (isNaN(diffMs) || diffMs < 0) return '0s';

  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return `${seconds}s`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;

  const days = Math.floor(hours / 24);
  return `${days}d`;
}

/**
 * Compute human pod status identical to `kubectl get pods`
 * @param {Object} pod
 * @returns {string}
 */
export function computePodStatus(pod) {
  if (pod.metadata?.deletionTimestamp) {
    return 'Terminating';
  }

  // 1. Check init container statuses
  const initStatuses = pod.status?.initContainerStatuses || [];
  for (let i = 0; i < initStatuses.length; i++) {
    const cs = initStatuses[i];
    if (cs.state?.terminated) {
      if (cs.state.terminated.exitCode === 0 || cs.state.terminated.reason === 'Completed') {
        continue;
      }
      return cs.state.terminated.reason ? `Init:${cs.state.terminated.reason}` : `Init:ExitCode:${cs.state.terminated.exitCode}`;
    }
    if (cs.state?.waiting && cs.state.waiting.reason && cs.state.waiting.reason !== 'PodInitializing') {
      return `Init:${cs.state.waiting.reason}`;
    }
    if (cs.state?.running) {
      return `Init:${i}/${initStatuses.length}`;
    }
  }

  // 2. Check regular container statuses
  const containerStatuses = pod.status?.containerStatuses || [];
  let hasRunning = false;
  let hasWaiting = null;
  let hasTerminated = null;

  for (const cs of containerStatuses) {
    if (cs.state?.waiting?.reason) {
      hasWaiting = cs.state.waiting.reason;
    } else if (cs.state?.terminated?.reason) {
      hasTerminated = cs.state.terminated.reason;
    } else if (cs.state?.running) {
      hasRunning = true;
    }
  }

  if (hasWaiting) {
    return hasWaiting;
  }

  if (pod.status?.phase === 'Succeeded') {
    return 'Completed';
  }

  if (hasTerminated && !hasRunning) {
    return hasTerminated;
  }

  return pod.status?.phase || 'Unknown';
}

/**
 * Query all pods with detailed information matching `kubectl get pods -A -o wide`
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} [options.namespace]
 * @returns {Promise<Array<Object>>}
 */
export async function getPodsWide({ clusterName = 'vigilante-dev', namespace = null, throwOnError = false } = {}) {
  const args = ['get', 'pods'];
  if (namespace && namespace !== 'all') {
    args.push('-n', assertDnsLabel(namespace, 'namespace'));
  } else {
    args.push('-A');
  }

  if (clusterName) {
    args.push(...(await getClusterContextArgs(assertDnsLabel(clusterName, 'clusterName'))));
  }

  args.push('--request-timeout=4s', '-o', 'json');

  try {
    const { stdout } = await execa('kubectl', args, { env: getKubeExecutionEnv() });
    const parsed = JSON.parse(stdout || '{"items":[]}');
    const items = parsed.items || [];

    return items.map((pod) => {
      const totalContainers = pod.spec?.containers?.length || 0;
      const readyContainers = (pod.status?.containerStatuses || []).filter(c => c.ready).length;
      const readyStr = `${readyContainers}/${totalContainers}`;

      const totalRestarts = (pod.status?.containerStatuses || []).reduce(
        (sum, c) => sum + (c.restartCount || 0),
        0
      );

      const status = computePodStatus(pod);
      const age = formatAge(pod.metadata?.creationTimestamp);
      const ip = pod.status?.podIP || '<none>';
      const node = pod.spec?.nodeName || '<none>';
      const nominatedNode = pod.status?.nominatedNodeName || '<none>';
      const readinessGates = (pod.spec?.readinessGates?.length || 0) > 0 ? String(pod.spec.readinessGates.length) : '<none>';

      return {
        namespace: pod.metadata?.namespace || 'default',
        name: pod.metadata?.name || 'unknown',
        ready: readyStr,
        readyCount: readyContainers,
        totalCount: totalContainers,
        status,
        restarts: totalRestarts,
        age,
        ip,
        node,
        nominatedNode,
        readinessGates,
        creationTimestamp: pod.metadata?.creationTimestamp
      };
    });
  } catch (err) {
    logger.debug('PODS:GET', `kubectl get pods query failed: ${err.message}`);
    if (throwOnError) throw err;
    return [];
  }
}

/**
 * Deep compare two pod arrays to avoid redundant state updates and UI re-renders
 * @param {Array<Object>} a
 * @param {Array<Object>} b
 * @returns {boolean}
 */
export function arePodsEqual(a, b) {
  if (a === b) return true;
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const p1 = a[i];
    const p2 = b[i];
    if (
      p1.namespace !== p2.namespace ||
      p1.name !== p2.name ||
      p1.ready !== p2.ready ||
      p1.status !== p2.status ||
      p1.restarts !== p2.restarts ||
      p1.age !== p2.age ||
      p1.ip !== p2.ip ||
      p1.node !== p2.node
    ) {
      return false;
    }
  }
  return true;
}

/**
 * Set up a live poller for pods matching `kubectl get pods -A -o wide`
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} [options.namespace]
 * @param {number} [options.intervalMs]
 * @param {Function} options.onUpdate
 * @param {Function} [options.onError]
 * @returns {Function} stop polling function
 */
export function watchPodsWide({
  clusterName = 'vigilante-dev',
  namespace = null,
  intervalMs = 2000,
  onUpdate,
  onError = null
}) {
  let active = true;
  let timerId = null;
  let lastPods = null;

  async function poll() {
    if (!active) return;
    try {
      const pods = await getPodsWide({ clusterName, namespace });
      if (active && onUpdate) {
        if (!lastPods || !arePodsEqual(lastPods, pods)) {
          lastPods = pods;
          onUpdate(pods);
        }
      }
    } catch (err) {
      if (active && onError) {
        onError(err);
      }
    } finally {
      if (active) {
        timerId = setTimeout(poll, intervalMs);
      }
    }
  }

  // Initial fetch immediately
  poll();

  return () => {
    active = false;
    if (timerId) {
      clearTimeout(timerId);
      timerId = null;
    }
  };
}

/**
 * Open text content in the system pager ($PAGER or less -R) and wait for user to exit
 * @param {string} content
 * @param {string} filenameHint
 */
export function openInSystemPager(content, filenameHint = 'output.txt') {
  if (!content) return;
  const pager = process.env.PAGER || 'less -R';
  let tmpDir = null;

  try {
    tmpDir = fsSync.mkdtempSync(path.join(os.tmpdir(), 'vigilante-pager-'), { mode: 0o700 });
    fsSync.chmodSync(tmpDir, 0o700);
    const tmpFile = path.join(tmpDir, sanitizePathComponent(filenameHint));
    fsSync.writeFileSync(tmpFile, content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });

    runInteractiveTerminal(() => {
      try {
        const parts = pager.trim().split(/\s+/);
        const bin = parts[0];
        const args = [...parts.slice(1), tmpFile];
        spawnSync(bin, args, {
          stdio: 'inherit'
        });
      } catch (err) {
        logger.error('PODS:PAGER', `Failed to open pager: ${err.message}`, err);
      }
    });
  } catch (err) {
    logger.warn('PODS:PAGER', `Could not write temporary file: ${err.message}`);
  } finally {
    if (tmpDir) {
      try {
        fsSync.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup error
      }
    }
  }
}

/**
 * Programmatically fetch logs for a pod
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} [options.namespace]
 * @param {string} options.podName
 * @param {string} [options.container]
 * @param {number} [options.tailLines]
 * @returns {Promise<string>}
 */
export async function getPodLogs({ clusterName = 'vigilante-dev', namespace = 'default', podName, container = null, tailLines = 100 } = {}) {
  if (!podName) return 'No pod specified';
  const cleanPod = assertDnsLabel(podName, 'podName');
  const cleanNs = assertDnsLabel(namespace, 'namespace');
  const lines = Number(tailLines);
  if (!Number.isInteger(lines) || lines < 1 || lines > 10000) {
    throw new Error(`Invalid tailLines '${tailLines}': expected integer between 1 and 10000`);
  }
  const args = ['logs', cleanPod, '-n', cleanNs, `--tail=${lines}`];
  if (container) {
    args.push('-c', assertContainerName(container));
  }
  if (clusterName) {
    args.push(...(await getClusterContextArgs(assertDnsLabel(clusterName, 'clusterName'))));
  }
  try {
    const { stdout } = await execa('kubectl', args, { env: getKubeExecutionEnv() });
    return stdout || '(No logs returned)';
  } catch (err) {
    return `Error retrieving logs for ${cleanNs}/${cleanPod}: ${err.message}`;
  }
}

/**
 * Programmatically describe a pod
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} [options.namespace]
 * @param {string} options.podName
 * @returns {Promise<string>}
 */
export async function describePod({ clusterName = 'vigilante-dev', namespace = 'default', podName } = {}) {
  if (!podName) return 'No pod specified';
  const cleanPod = assertDnsLabel(podName, 'podName');
  const cleanNs = assertDnsLabel(namespace, 'namespace');
  const args = ['describe', 'pod', cleanPod, '-n', cleanNs];
  if (clusterName) {
    args.push(...(await getClusterContextArgs(assertDnsLabel(clusterName, 'clusterName'))));
  }
  try {
    const { stdout } = await execa('kubectl', args, { env: getKubeExecutionEnv() });
    return stdout || '(No describe output returned)';
  } catch (err) {
    return `Error describing ${cleanNs}/${cleanPod}: ${err.message}`;
  }
}

/**
 * Interactively describe a pod with the system pager
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} options.namespace
 * @param {string} options.podName
 */
export function describePodInteractive({ clusterName = 'vigilante-dev', namespace, podName }) {
  if (!podName || !namespace) return;
  const cleanPod = assertDnsLabel(podName, 'podName');
  const cleanNs = assertDnsLabel(namespace, 'namespace');
  const cleanCluster = clusterName ? assertDnsLabel(clusterName, 'clusterName') : '';
  logger.info('PODS:DESCRIBE', `Running kubectl describe pod ${cleanPod} -n ${cleanNs}`);
  let output = '';
  try {
    const args = ['describe', 'pod', cleanPod, '-n', cleanNs, ...getSyncClusterContextArgs(cleanCluster)];
    const res = spawnSync('kubectl', args, { encoding: 'utf8', env: getKubeExecutionEnv() });
    output = res.stdout || res.stderr || 'No describe output available.';
  } catch (err) {
    output = `Failed to execute kubectl describe: ${err.message}`;
  }
  openInSystemPager(output, `describe-${cleanNs}-${cleanPod}.txt`);
}

/**
 * Interactively view pod logs in the system pager
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} options.namespace
 * @param {string} options.podName
 */
export function viewPodLogsInteractive({ clusterName = 'vigilante-dev', namespace, podName }) {
  if (!podName || !namespace) return;
  const cleanPod = assertDnsLabel(podName, 'podName');
  const cleanNs = assertDnsLabel(namespace, 'namespace');
  const cleanCluster = clusterName ? assertDnsLabel(clusterName, 'clusterName') : '';
  logger.info('PODS:LOGS', `Viewing kubectl logs for ${cleanPod} -n ${cleanNs}`);
  let output = '';
  try {
    const args = ['logs', '--tail=5000', cleanPod, '-n', cleanNs, ...getSyncClusterContextArgs(cleanCluster), '--all-containers=true'];
    const res = spawnSync('kubectl', args, { encoding: 'utf8', env: getKubeExecutionEnv() });
    output = res.stdout || res.stderr || 'No logs available for this pod.';
  } catch (err) {
    output = `Failed to retrieve logs: ${err.message}`;
  }
  openInSystemPager(output, `logs-${cleanNs}-${cleanPod}.log`);
}

/**
 * Alias for viewPodLogsInteractive
 */
export const streamPodLogsInteractive = viewPodLogsInteractive;

/**
 * Interactively open a shell into a pod
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} options.namespace
 * @param {string} options.podName
 */
export function openPodShellInteractive({ clusterName = 'vigilante-dev', namespace, podName }) {
  if (!podName || !namespace) return;
  const cleanPod = assertDnsLabel(podName, 'podName');
  const cleanNs = assertDnsLabel(namespace, 'namespace');
  const cleanCluster = clusterName ? assertDnsLabel(clusterName, 'clusterName') : '';
  logger.info('PODS:SHELL', `Opening shell into pod ${cleanPod} -n ${cleanNs}`);
  runInteractiveTerminal(() => {
    console.log(`\x1b[1;32m=== Connecting interactive shell to pod: ${cleanNs}/${cleanPod} (Type 'exit' to return to Vigilante) ===\x1b[0m\n`);
    const args = ['exec', '-it', cleanPod, '-n', cleanNs, ...getSyncClusterContextArgs(cleanCluster), '--', '/bin/sh', '-c', 'command -v bash >/dev/null 2>&1 && exec bash || exec sh'];
    spawnSync('kubectl', args, { stdio: 'inherit', env: getKubeExecutionEnv() });
  });
}
