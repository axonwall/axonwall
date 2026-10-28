import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const LOG_DIR_PATH = path.join(os.homedir(), '.config', 'vigilante');
const LOG_FILE_PATH = path.join(LOG_DIR_PATH, 'vigilante.log');
const FALLBACK_LOG_DIR_PATH = path.join(os.tmpdir(), `vigilante-logs-${typeof process.getuid === 'function' ? process.getuid() : process.pid}`);
const FALLBACK_LOG_FILE_PATH = path.join(FALLBACK_LOG_DIR_PATH, 'vigilante.log');

function resolveSafeLogFile() {
  for (const [dirPath, filePath] of [[LOG_DIR_PATH, LOG_FILE_PATH], [FALLBACK_LOG_DIR_PATH, FALLBACK_LOG_FILE_PATH]]) {
    try {
      fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
      const dirStat = fs.lstatSync(dirPath);
      if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) continue;
      if (fs.existsSync(filePath)) {
        const fileStat = fs.lstatSync(filePath);
        if (fileStat.isSymbolicLink() || !fileStat.isFile()) continue;
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

    // Synchronous append so logs are never lost on immediate exit or crash
    fs.appendFileSync(targetLogPath, entry, { encoding: 'utf8', mode: 0o600 });
  } catch {
    // Fail-safe: silently continue if logging fails
  }
}

export const logger = {
  debug: (tag, message, details) => writeDebugLog('DEBUG', tag, message, details),
  info: (tag, message, details) => writeDebugLog('INFO', tag, message, details),
  warn: (tag, message, details) => writeDebugLog('WARN', tag, message, details),
  error: (tag, message, details) => writeDebugLog('ERROR', tag, message, details),
  getLogPath: () => LOG_FILE_PATH
};
