import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

function getDefaultLogCandidates(uid) {
  const logDirPath = path.join(os.homedir(), '.config', 'vigilante');
  const logFilePath = path.join(logDirPath, 'vigilante.log');
  const fallbackDirPath = path.join(os.tmpdir(), `vigilante-logs-${uid !== null ? uid : process.pid}`);
  const fallbackFilePath = path.join(fallbackDirPath, 'vigilante.log');
  return [
    [logDirPath, logFilePath],
    [fallbackDirPath, fallbackFilePath]
  ];
}

export function resolveSafeLogFile(candidates = null, deps = {}) {
  const getuidFn = deps.getuid ?? (typeof process.getuid === 'function' ? () => process.getuid() : null);
  const uid = typeof getuidFn === 'function' ? getuidFn() : null;
  const lstat = deps.lstatSync || fs.lstatSync;
  const mkdir = deps.mkdirSync || fs.mkdirSync;
  const targets = candidates || getDefaultLogCandidates(uid);

  for (const [dirPath, filePath] of targets) {
    try {
      mkdir(dirPath, { recursive: true, mode: 0o700 });
      const dirStat = lstat(dirPath);
      if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) continue;
      if (uid !== null && dirStat.uid !== uid) continue;
      if ((dirStat.mode & 0o077) !== 0) continue;

      try {
        const fileStat = lstat(filePath);
        if (fileStat.isSymbolicLink() || !fileStat.isFile()) continue;
        if (uid !== null && fileStat.uid !== uid) continue;
      } catch (err) {
        if (!err || err.code !== 'ENOENT') continue;
      }
      return filePath;
    } catch {
      // Try fallback directory
    }
  }
  return null;
}

/**
 * Append a formatted log entry to ~/.config/vigilante/vigilante.log
 * @param {string} level - 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'
 * @param {string} tag - Component or action tag, e.g. 'UI:KEY' or 'CLUSTER'
 * @param {string} message - Primary log text
 * @param {any} [details] - Optional extra metadata or error object
 */
export function writeDebugLog(level, tag, message, details = null) {
  try {
    const timestamp = new Date().toISOString();
    let entry = `[${timestamp}] [${level.padEnd(5)}] [${tag}] ${message}`;

    if (details !== null && details !== undefined) {
      if (details instanceof Error) {
        entry += `\n  Stack: ${details.stack || details.message}`;
      } else if (typeof details === 'object') {
        try {
          entry += `\n  Data: ${JSON.stringify(details)}`;
        } catch {
          entry += `\n  Data: [Circular or unstringifiable object]`;
        }
      } else {
        entry += `\n  Details: ${details}`;
      }
    }

    entry += '\n';

    const targetLogPath = resolveSafeLogFile();
    if (!targetLogPath) return;

    // Synchronous non-following append so logs are never lost or redirected via symlinks
    const flags = fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW || 0);
    const fd = fs.openSync(targetLogPath, flags, 0o600);
    try {
      const fdStat = fs.fstatSync(fd);
      const uid = typeof process.getuid === 'function' ? process.getuid() : null;
      if (!fdStat.isFile() || (uid !== null && fdStat.uid !== uid)) {
        return;
      }
      fs.writeSync(fd, entry, null, 'utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // Fail-safe: silently continue if logging fails
  }
}

export const logger = {
  debug: (tag, message, details) => writeDebugLog('DEBUG', tag, message, details),
  info: (tag, message, details) => writeDebugLog('INFO', tag, message, details),
  warn: (tag, message, details) => writeDebugLog('WARN', tag, message, details),
  error: (tag, message, details) => writeDebugLog('ERROR', tag, message, details),
  getLogPath: () => path.join(os.homedir(), '.config', 'vigilante', 'vigilante.log')
};
