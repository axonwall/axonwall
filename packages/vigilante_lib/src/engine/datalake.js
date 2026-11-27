/**
 * High-Throughput Embedded Security Data Lake Engine
 * In-process, zero-dependency SQL analytics over security telemetry
 * (Falco alerts, Zeek conn/dns logs, Suricata eve, K8s audit, and CTI hits).
 * Supports retrospective threat hunting against newly ingested IOCs.
 */

import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getVigilanteDatalakeDir } from './config.js';
import { logger } from '../utils/logger.js';

const require = createRequire(import.meta.url);

let DatabaseSync = null;
let sqliteConstants = null;
try {
  const sqlite = require('node:sqlite');
  DatabaseSync = sqlite.DatabaseSync || null;
  sqliteConstants = sqlite.constants || null;
} catch {
  try {
    DatabaseSync = require('better-sqlite3');
  } catch {
    DatabaseSync = null;
  }
}

let dbInstance = null;
let activeBackend = 'sqlite';

const CREATE_DUCKDB_EVENTS_SQL = `
  CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR PRIMARY KEY,
    event_type VARCHAR NOT NULL,
    source_pod VARCHAR,
    source_ip VARCHAR,
    dest_ip VARCHAR,
    dest_port INTEGER,
    severity VARCHAR NOT NULL,
    mitre_technique VARCHAR,
    indicator VARCHAR,
    raw_json VARCHAR,
    timestamp VARCHAR NOT NULL
  );
`;

function normalizeRowValues(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.map((row) => {
    if (!row || typeof row !== 'object') return row;
    const out = {};
    for (const [k, v] of Object.entries(row)) {
      out[k] = typeof v === 'bigint' ? Number(v) : v;
    }
    return out;
  });
}

function createDuckDbAdapter(duckdbPkg, dbPath) {
  // Support both @duckdb/node-api (DuckDBInstance) and legacy duckdb (Database)
  if (duckdbPkg.DuckDBInstance && typeof duckdbPkg.DuckDBInstance.create === 'function') {
    const readyPromise = (async () => {
      const instance = await duckdbPkg.DuckDBInstance.create(dbPath);
      const conn = await instance.connect();
      await conn.run('SET enable_external_access=false; SET allow_community_extensions=false;');
      await conn.run(CREATE_DUCKDB_EVENTS_SQL);
      return { instance, conn };
    })();

    const runOnConn = async (sql, params = []) => {
      const { conn } = await readyPromise;
      if (params.length === 0) {
        return conn.run(sql);
      }
      if (typeof conn.prepare === 'function') {
        const prepared = await conn.prepare(sql);
        try {
          for (let i = 0; i < params.length; i++) {
            const val = params[i];
            if (val === null || val === undefined) prepared.bindNull?.(i + 1);
            else if (typeof val === 'number' && Number.isInteger(val)) prepared.bindInteger?.(i + 1, val);
            else if (typeof val === 'number') prepared.bindDouble?.(i + 1, val);
            else prepared.bindVarchar?.(i + 1, String(val));
          }
          return await prepared.run();
        } finally {
          prepared.destroySync?.();
        }
      }
      return conn.run(sql, params);
    };

    const allOnConn = async (sql, params = []) => {
      const { conn } = await readyPromise;
      let reader;
      if (params.length > 0 && typeof conn.prepare === 'function') {
        const prepared = await conn.prepare(sql);
        try {
          for (let i = 0; i < params.length; i++) {
            const val = params[i];
            if (val === null || val === undefined) prepared.bindNull?.(i + 1);
            else if (typeof val === 'number' && Number.isInteger(val)) prepared.bindInteger?.(i + 1, val);
            else if (typeof val === 'number') prepared.bindDouble?.(i + 1, val);
            else prepared.bindVarchar?.(i + 1, String(val));
          }
          reader = await prepared.runAndReadAll();
        } finally {
          prepared.destroySync?.();
        }
      } else if (typeof conn.runAndReadAll === 'function') {
        reader = await conn.runAndReadAll(sql, params.length > 0 ? params : undefined);
      } else {
        reader = await conn.run(sql);
      }
      const rawRows = reader?.getRowObjectsJson?.() ?? reader?.getRowObjects?.() ?? [];
      return normalizeRowValues(rawRows);
    };

    return {
      backend: 'duckdb',
      rawDb: readyPromise,
      exec: (sql) => runOnConn(sql),
      close: async () => {
        const { instance, conn } = await readyPromise;
        await (conn.closeSync?.() ?? conn.close?.());
        await (instance.closeSync?.() ?? instance.close?.());
      },
      prepare: (sql) => ({
        all: (...params) => allOnConn(sql, params),
        run: (...params) => runOnConn(sql, params)
      })
    };
  }

  const ddb = new duckdbPkg.Database(dbPath);
  const execCb = (sql) =>
    new Promise((resolve, reject) => {
      if (typeof ddb.exec === 'function') {
        ddb.exec(sql, (err) => {
          if (err) reject(err);
          else resolve();
        });
      } else {
        ddb.run(sql, (err) => {
          if (err) reject(err);
          else resolve();
        });
      }
    });

  const runCb = (sql, params) =>
    new Promise((resolve, reject) => {
      ddb.run(sql, ...params, (err, res) => {
        if (err) reject(err);
        else resolve(res);
      });
    });

  const allCb = (sql, params) =>
    new Promise((resolve, reject) => {
      ddb.all(sql, ...params, (err, res) => {
        if (err) reject(err);
        else resolve(normalizeRowValues(res || []));
      });
    });

  const readyPromise = (async () => {
    await execCb('SET enable_external_access=false; SET allow_community_extensions=false;');
    await execCb(CREATE_DUCKDB_EVENTS_SQL);
  })();

  return {
    backend: 'duckdb',
    rawDb: ddb,
    exec: async (sql) => {
      await readyPromise;
      return execCb(sql);
    },
    close: async () => {
      try {
        await readyPromise;
      } catch {
        // Proceed to close even if startup failed
      }
      if (typeof ddb.close === 'function') {
        await new Promise((resolve) => {
          if (ddb.close.length >= 1) ddb.close(() => resolve());
          else {
            ddb.close();
            resolve();
          }
        });
      }
    },
    prepare: (sql) => ({
      all: async (...params) => {
        await readyPromise;
        return allCb(sql, params);
      },
      run: async (...params) => {
        await readyPromise;
        return runCb(sql, params);
      }
    })
  };
}

/**
 * Attempt to load the official DuckDB driver if installed
 * @returns {Object|null}
 */
function tryLoadDuckDb() {
  try {
    return require('duckdb');
  } catch {
    try {
      return require('@duckdb/node-api');
    } catch {
      return null;
    }
  }
}

/**
 * Returns the currently active Data Lake SQL engine backend ('sqlite' or 'duckdb')
 * @returns {'sqlite'|'duckdb'}
 */
export function getDataLakeBackend() {
  return activeBackend;
}

/**
 * Get or initialize embedded Data Lake database instance.
 * Defaults to built-in zero-dependency SQLite (free first),
 * with support for official DuckDB when requested/installed.
 * @param {string|Object} [customPathOrOptions='']
 * @param {Object} [options={}]
 * @returns {DatabaseSync|Object}
 */
export function initDataLake(customPathOrOptions = '', options = {}) {
  let opts = options;
  let dbPath = customPathOrOptions;

  if (typeof customPathOrOptions === 'object' && customPathOrOptions !== null) {
    opts = customPathOrOptions;
    dbPath = opts.customPath || opts.path || '';
  }

  if (dbInstance) return dbInstance;

  const preferredBackend = (opts.backend || process.env.VIGILANTE_DATALAKE_BACKEND || 'auto').toLowerCase();
  const duckdbPkg = (preferredBackend === 'duckdb' || preferredBackend === 'official')
    ? (opts.duckdbModule || tryLoadDuckDb())
    : null;

  if ((preferredBackend === 'duckdb' || preferredBackend === 'official') && !duckdbPkg) {
    logger.warn(
      'DATALAKE',
      "Official DuckDB backend requested ('duckdb'), but 'duckdb' package is not installed. Falling back to built-in zero-dependency high-throughput SQLite engine."
    );
  }

  if (!dbPath) {
    const lakeDir = getVigilanteDatalakeDir();
    if (!fsSync.existsSync(lakeDir)) {
      fsSync.mkdirSync(lakeDir, { recursive: true });
    }
    const ext = (duckdbPkg && (preferredBackend === 'duckdb' || preferredBackend === 'official')) ? 'duckdb' : 'db';
    dbPath = path.join(lakeDir, `events.${ext}`);
  }

  // Official DuckDB Adapter (when installed and requested)
  if (duckdbPkg && (preferredBackend === 'duckdb' || preferredBackend === 'official')) {
    activeBackend = 'duckdb';
    dbInstance = createDuckDbAdapter(duckdbPkg, dbPath);
    logger.info('DATALAKE', `Initialized Official DuckDB Security Data Lake at ${dbPath}`);
    return dbInstance;
  }

  // Free First: Built-in Node.js SQLite (DatabaseSync)
  activeBackend = 'sqlite';
  if (!DatabaseSync) {
    throw new Error(
      "SQLite engine unavailable: built-in 'node:sqlite' requires Node.js >= 22.5.0, or install 'better-sqlite3' / 'duckdb'."
    );
  }
  const db = new DatabaseSync(dbPath);
  if (typeof db.enableDefensive === 'function') {
    db.enableDefensive(true);
  }
  if (typeof db.enableLoadExtension === 'function') {
    db.enableLoadExtension(false);
  }

  // Initialize unified security events schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      source_pod TEXT,
      source_ip TEXT,
      dest_ip TEXT,
      dest_port INTEGER,
      severity TEXT NOT NULL,
      mitre_technique TEXT,
      indicator TEXT,
      raw_json TEXT,
      timestamp TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_src ON security_events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_events_dst ON security_events(dest_ip);
    CREATE INDEX IF NOT EXISTS idx_events_indicator ON security_events(indicator);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
  `);

  logger.info('DATALAKE', `Initialized Security Data Lake (${activeBackend}) at ${dbPath}`);
  dbInstance = db;
  return db;
}

/**
 * Close Data Lake database instance (useful for clean test teardowns)
 */
export function closeDataLake() {
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // Ignore
    }
    dbInstance = null;
    activeBackend = 'sqlite';
  }
}

/**
 * Ingest an array of normalized security events asynchronously (DuckDB)
 * @private
 */

async function ingestSecurityEventsAsync(db, eventType, events) {
  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO security_events (
      id, event_type, source_pod, source_ip, dest_ip, dest_port, severity, mitre_technique, indicator, raw_json, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  await db.exec('BEGIN TRANSACTION');
  let inserted = 0;

  try {
    for (const ev of events) {
      const id = ev.id || `${eventType}-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
      const srcPod = ev.sourcePod || ev.pod || ev.podName || null;
      const srcIp = ev.sourceIp || ev.srcIp || ev.src || null;
      const dstIp = ev.destIp || ev.dstIp || ev.dst || null;
      const dstPort = ev.destPort || ev.dstPort || ev.port || null;
      const severity = (ev.severity || 'INFO').toUpperCase();
      const mitre = ev.mitreTechnique || ev.technique || null;
      const indicator = ev.indicator || ev.ioc || ev.query || null;
      const rawJson = typeof ev === 'string' ? ev : JSON.stringify(ev);
      const ts = ev.timestamp || new Date().toISOString();

      await insertStmt.run(id, eventType, srcPod, srcIp, dstIp, dstPort ? Number(dstPort) : null, severity, mitre, indicator, rawJson, ts);
      inserted++;
    }
    await db.exec('COMMIT');
    logger.info('DATALAKE', `Ingested ${inserted} [${eventType}] records into Data Lake.`);
  } catch (err) {
    try {
      await db.exec('ROLLBACK');
    } catch {
      // Ignore rollback errors
    }
    logger.error('DATALAKE', `Ingestion failed: ${err.message}`);
    throw err;
  }

  return inserted;
}

/**
 * Ingest an array of normalized security events into the Data Lake
 * @param {string} eventType e.g. 'falco', 'zeek', 'suricata', 'audit', 'canary'
 * @param {Array<Object>} events List of event objects
 * @returns {number|Promise<number>} Count of successfully ingested records
 */
export function ingestSecurityEvents(eventType, events = []) {
  const db = initDataLake();
  if (!events || events.length === 0) return 0;

  if (activeBackend === 'duckdb') {
    return ingestSecurityEventsAsync(db, eventType, events);
  }

  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO security_events (
      id, event_type, source_pod, source_ip, dest_ip, dest_port, severity, mitre_technique, indicator, raw_json, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  db.exec('BEGIN TRANSACTION');
  let inserted = 0;

  try {
    for (const ev of events) {
      const id = ev.id || `${eventType}-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
      const srcPod = ev.sourcePod || ev.pod || ev.podName || null;
      const srcIp = ev.sourceIp || ev.srcIp || ev.src || null;
      const dstIp = ev.destIp || ev.dstIp || ev.dst || null;
      const dstPort = ev.destPort || ev.dstPort || ev.port || null;
      const severity = (ev.severity || 'INFO').toUpperCase();
      const mitre = ev.mitreTechnique || ev.technique || null;
      const indicator = ev.indicator || ev.ioc || ev.query || null;
      const rawJson = typeof ev === 'string' ? ev : JSON.stringify(ev);
      const ts = ev.timestamp || new Date().toISOString();

      insertStmt.run(id, eventType, srcPod, srcIp, dstIp, dstPort ? Number(dstPort) : null, severity, mitre, indicator, rawJson, ts);
      inserted++;
    }
    db.exec('COMMIT');
    logger.info('DATALAKE', `Ingested ${inserted} [${eventType}] records into Data Lake.`);
  } catch (err) {
    db.exec('ROLLBACK');
    logger.error('DATALAKE', `Ingestion failed: ${err.message}`);
    throw err;
  }

  return inserted;
}

const ALLOWED_DATALAKE_TABLES = new Set(['security_events']);
const MAX_DATALAKE_SQL_LENGTH = 16384;
const MAX_DATALAKE_ROWS = 1000;
const MAX_DATALAKE_PARAMS = 64;
const MAX_QUERY_DEPTH = 16;
const MAX_TABLE_REFS = 8;
const MAX_PRINTF_WIDTH = 4096;
const MAX_REPEAT_WIDTH = 4096;

const FORBIDDEN_DATALAKE_KEYWORDS = new Set([
  'ATTACH', 'DETACH', 'PRAGMA', 'COPY', 'EXPORT', 'IMPORT', 'INSTALL', 'LOAD',
  'SET', 'RESET', 'CALL', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER',
  'CREATE', 'REPLACE', 'VACUUM', 'MERGE', 'TRUNCATE', 'GRANT', 'REVOKE',
  'READ_TEXT', 'READ_BLOB', 'READ_CSV', 'READ_CSV_AUTO', 'READ_JSON',
  'READ_JSON_AUTO', 'READ_PARQUET', 'READ_XLSX', 'SNIFF_CSV', 'PARQUET_SCAN',
  'SQLITE_MASTER', 'SQLITE_TEMP_MASTER', 'SQLITE_SCHEMA', 'SQLITE_TEMP_SCHEMA',
  'GLOB', 'HTTPFS', 'LOAD_EXTENSION', 'EXEC', 'EXECUTE',
  'RECURSIVE', 'ZEROBLOB', 'RANDOMBLOB', 'FTS3_TOKENIZER',
  'GENERATE_SERIES', 'RANGE', 'UNNEST', 'STR_REPEAT', 'CHAR_REPEAT'
]);

const FORBIDDEN_SQLITE_FUNCTIONS = new Set([
  'zeroblob',
  'randomblob',
  'load_extension',
  'sqlite_offset',
  'fts3_tokenizer',
  'edit',
  'writefile',
  'readfile'
]);

const CLAUSE_STOP_KEYWORDS = new Set([
  'WHERE', 'GROUP', 'HAVING', 'ORDER', 'LIMIT', 'OFFSET', 'UNION',
  'INTERSECT', 'EXCEPT', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'FULL', 'CROSS',
  'NATURAL', 'ON', 'USING', 'WINDOW', 'QUALIFY', 'FOR', 'FETCH'
]);

function tokenizeDataLakeSql(sql) {
  const tokens = [];
  let i = 0;
  const n = sql.length;

  while (i < n) {
    const ch = sql[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    // Line comment
    if (ch === '-' && sql[i + 1] === '-') {
      i += 2;
      while (i < n && sql[i] !== '\n' && sql[i] !== '\r') i++;
      continue;
    }

    // Block comment
    if (ch === '/' && sql[i + 1] === '*') {
      i += 2;
      const closeIdx = sql.indexOf('*/', i);
      if (closeIdx === -1) {
        throw new Error('Unterminated block comment in Data Lake SQL query');
      }
      if (sql.slice(i, closeIdx).includes('/*')) {
        throw new Error('Nested block comments are not permitted in Data Lake SQL query');
      }
      i = closeIdx + 2;
      continue;
    }

    // Single-quoted string literal (skip content for keyword/semicolon checks)
    if (ch === "'") {
      const start = i;
      i++;
      let closed = false;
      while (i < n) {
        if (sql[i] === "'") {
          if (sql[i + 1] === "'") {
            i += 2;
            continue;
          }
          i++;
          closed = true;
          break;
        }
        i++;
      }
      if (!closed) {
        throw new Error('Unterminated string literal in Data Lake SQL query');
      }
      tokens.push({ type: 'string', raw: sql.slice(start, i), value: sql.slice(start + 1, i - 1), start, end: i });
      continue;
    }

    // Double-quoted or backtick identifier
    if (ch === '"' || ch === '`') {
      const quote = ch;
      const start = i;
      i++;
      let ident = '';
      let closed = false;
      while (i < n) {
        if (sql[i] === quote) {
          if (sql[i + 1] === quote) {
            ident += quote;
            i += 2;
            continue;
          }
          i++;
          closed = true;
          break;
        }
        ident += sql[i++];
      }
      if (!closed) {
        throw new Error('Unterminated quoted identifier in Data Lake SQL query');
      }
      tokens.push({ type: 'ident', raw: sql.slice(start, i), value: ident, upper: ident.toUpperCase(), start, end: i });
      continue;
    }

    // Numbers
    if (/[0-9]/.test(ch)) {
      const start = i;
      while (i < n && /[0-9.eExXa-fA-F]/.test(sql[i])) i++;
      tokens.push({ type: 'number', raw: sql.slice(start, i), value: sql.slice(start, i), start, end: i });
      continue;
    }

    // Identifiers / SQL keywords
    if (/[A-Za-z_$]/.test(ch)) {
      const start = i;
      while (i < n && /[A-Za-z0-9_$]/.test(sql[i])) i++;
      const word = sql.slice(start, i);
      tokens.push({ type: 'word', raw: word, value: word, upper: word.toUpperCase(), start, end: i });
      continue;
    }

    // Punctuation & operators
    if ('(),.;?*+-/<>=!|&:%~'.includes(ch)) {
      tokens.push({ type: 'punct', raw: ch, value: ch, start: i, end: i + 1 });
      i++;
      continue;
    }

    throw new Error(`Unexpected character '${ch}' in Data Lake SQL query`);
  }

  return tokens;
}

function isForbiddenToken(tok) {
  if (!tok || (tok.type !== 'word' && tok.type !== 'ident')) return false;
  const u = tok.upper;
  return (
    FORBIDDEN_DATALAKE_KEYWORDS.has(u) ||
    u.startsWith('PRAGMA_') ||
    u.startsWith('DUCKDB_') ||
    u.startsWith('SQLITE_') ||
    u.startsWith('READ_')
  );
}

function findMatchingParen(tokens, openIdx) {
  let depth = 1;
  let i = openIdx + 1;
  while (i < tokens.length && depth > 0) {
    if (tokens[i].value === '(') depth++;
    else if (tokens[i].value === ')') depth--;
    if (depth === 0) return i;
    i++;
  }
  throw new Error('Unbalanced parentheses in Data Lake SQL query');
}

function splitTopLevelCallArgs(tokens, openIdx, closeIdx) {
  const args = [];
  let current = [];
  let depth = 0;
  for (let i = openIdx + 1; i < closeIdx; i++) {
    const t = tokens[i];
    if (t.value === '(') {
      depth++;
      current.push(t);
    } else if (t.value === ')') {
      depth--;
      current.push(t);
    } else if (t.value === ',' && depth === 0) {
      args.push(current);
      current = [];
    } else {
      current.push(t);
    }
  }
  if (current.length > 0 || args.length > 0) {
    args.push(current);
  }
  return args;
}

function assertSafePrintfFormatString(fmt, fnName) {
  let i = 0;
  while (i < fmt.length) {
    const ch = fmt[i];
    if (ch === '{') {
      if (fmt[i + 1] === '{') {
        i += 2;
        continue;
      }
      const closeBrace = fmt.indexOf('}', i + 1);
      if (closeBrace !== -1) {
        const spec = fmt.slice(i + 1, closeBrace);
        if (spec.includes('{')) {
          throw new Error(`Nested format specifiers in ${fnName}() are forbidden in Data Lake queries`);
        }
        const colonIdx = spec.indexOf(':');
        if (colonIdx !== -1) {
          const fmtSpec = spec.slice(colonIdx + 1);
          const numMatches = fmtSpec.match(/\d+/g) || [];
          for (const numStr of numMatches) {
            if (Number(numStr) > MAX_PRINTF_WIDTH) {
              throw new Error(`${fnName}() format width '${numStr}' exceeds maximum allowed limit (${MAX_PRINTF_WIDTH})`);
            }
          }
        }
        i = closeBrace + 1;
        continue;
      }
    }
    if (ch !== '%') {
      i++;
      continue;
    }
    if (fmt[i + 1] === '%') {
      i += 2;
      continue;
    }
    i++;
    const rest = fmt.slice(i);
    const posMatch = rest.match(/^(\d+)\$/);
    if (posMatch) {
      i += posMatch[0].length;
    }
    while (i < fmt.length && "-+ #0'!".includes(fmt[i])) {
      i++;
    }
    if (fmt[i] === '*') {
      throw new Error(`Dynamic ${fnName}() width specifier (*) is forbidden in Data Lake queries`);
    }
    let widthStr = '';
    while (i < fmt.length && /[0-9]/.test(fmt[i])) {
      widthStr += fmt[i++];
    }
    if (widthStr && Number(widthStr) > MAX_PRINTF_WIDTH) {
      throw new Error(`${fnName}() width '${widthStr}' exceeds maximum allowed limit (${MAX_PRINTF_WIDTH})`);
    }
    if (fmt[i] === '.') {
      i++;
      if (fmt[i] === '*') {
        throw new Error(`Dynamic ${fnName}() precision specifier (.*) is forbidden in Data Lake queries`);
      }
      let precStr = '';
      while (i < fmt.length && /[0-9]/.test(fmt[i])) {
        precStr += fmt[i++];
      }
      if (precStr && Number(precStr) > MAX_PRINTF_WIDTH) {
        throw new Error(`${fnName}() precision '${precStr}' exceeds maximum allowed limit (${MAX_PRINTF_WIDTH})`);
      }
    }
    if (i < fmt.length) i++;
  }
}

function validateDangerousFunctionCalls(tokens) {
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if ((tok.type !== 'word' && tok.type !== 'ident') || tokens[i + 1]?.value !== '(') {
      continue;
    }
    const fn = tok.upper;
    const openIdx = i + 1;
    const closeIdx = findMatchingParen(tokens, openIdx);
    const args = splitTopLevelCallArgs(tokens, openIdx, closeIdx);

    if (fn === 'PRINTF' || fn === 'FORMAT') {
      if (args.length === 0 || args[0].length !== 1 || args[0][0].type !== 'string') {
        throw new Error(`${fn}() format argument must be a static string literal in Data Lake queries`);
      }
      assertSafePrintfFormatString(args[0][0].value, fn.toLowerCase());
    } else if (fn === 'REPEAT' || fn === 'LPAD' || fn === 'RPAD' || fn === 'SPACE') {
      const lenArgIdx = fn === 'SPACE' ? 0 : 1;
      const lenArg = args[lenArgIdx];
      if (!lenArg || lenArg.length !== 1 || lenArg[0].type !== 'number') {
        throw new Error(`${fn}() length argument must be a bounded numeric literal in Data Lake queries`);
      }
      const val = Number(lenArg[0].value);
      if (!Number.isFinite(val) || val < 0 || val > MAX_REPEAT_WIDTH) {
        throw new Error(`${fn}() length '${lenArg[0].value}' exceeds maximum allowed limit (${MAX_REPEAT_WIDTH})`);
      }
    }
  }
}

function advanceOptionalAliasAndColumns(tokens, cursor) {
  let pos = cursor;
  if (tokens[pos]?.type === 'word' && tokens[pos].upper === 'AS') {
    const aliasTok = tokens[pos + 1];
    if (!aliasTok || (aliasTok.type !== 'word' && aliasTok.type !== 'ident')) {
      throw new Error('Expected identifier after AS in Data Lake query');
    }
    pos += 2;
  } else if (
    tokens[pos] &&
    (tokens[pos].type === 'word' || tokens[pos].type === 'ident') &&
    !CLAUSE_STOP_KEYWORDS.has(tokens[pos].upper)
  ) {
    pos += 1;
  } else {
    return pos;
  }

  // Optional derived column alias list: e.g. AS t(c1, c2) or t(c1, c2)
  if (tokens[pos]?.value === '(') {
    const closeIdx = findMatchingParen(tokens, pos);
    for (let k = pos + 1; k < closeIdx; k++) {
      const colTok = tokens[k];
      if (colTok.value !== ',' && colTok.type !== 'word' && colTok.type !== 'ident') {
        throw new Error(`Invalid column alias token '${colTok.raw}' in Data Lake query`);
      }
    }
    pos = closeIdx + 1;
  }

  return pos;
}

function isQueryStart(tokens) {
  if (!tokens || tokens.length === 0) return false;
  let idx = 0;
  while (idx < tokens.length && tokens[idx].value === '(') {
    idx++;
  }
  const first = tokens[idx];
  return Boolean(first && first.type === 'word' && (first.upper === 'SELECT' || first.upper === 'WITH'));
}

function scanExpressionsForSubqueries(tokens, cteNames, depth, refCounter) {
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].value === '(') {
      const closeIdx = findMatchingParen(tokens, i);
      const inner = tokens.slice(i + 1, closeIdx);
      if (isQueryStart(inner)) {
        validateQueryTokens(inner, cteNames, depth + 1, refCounter);
      } else {
        scanExpressionsForSubqueries(inner, cteNames, depth + 1, refCounter);
      }
      i = closeIdx;
    }
  }
}

function validateParenthesizedJoinExpr(tokens, cteNames, depth, refCounter) {
  if (tokens.length === 0) {
    throw new Error('Empty parenthesized table reference in Data Lake query');
  }
  let cursor = validateTableRef(tokens, 0, cteNames, depth, refCounter);
  while (cursor < tokens.length) {
    const tok = tokens[cursor];
    if (tok.value === ',') {
      cursor = validateTableRef(tokens, cursor + 1, cteNames, depth, refCounter);
      continue;
    }
    if (tok.type === 'word' && (tok.upper === 'JOIN' || ['INNER', 'LEFT', 'RIGHT', 'FULL', 'CROSS', 'NATURAL', 'OUTER'].includes(tok.upper))) {
      while (cursor < tokens.length && tokens[cursor].type === 'word' && tokens[cursor].upper !== 'JOIN') {
        cursor++;
      }
      if (tokens[cursor]?.upper !== 'JOIN') {
        throw new Error('Malformed JOIN inside parenthesized table reference');
      }
      cursor = validateTableRef(tokens, cursor + 1, cteNames, depth, refCounter);
      if (tokens[cursor]?.upper === 'ON' || tokens[cursor]?.upper === 'USING') {
        const condStart = cursor + 1;
        while (cursor < tokens.length) {
          if (tokens[cursor].value === '(') {
            const closeIdx = findMatchingParen(tokens, cursor);
            scanExpressionsForSubqueries(tokens.slice(cursor + 1, closeIdx), cteNames, depth + 1, refCounter);
            cursor = closeIdx + 1;
            continue;
          }
          if (
            tokens[cursor].value === ',' ||
            (tokens[cursor].type === 'word' && ['JOIN', 'INNER', 'LEFT', 'RIGHT', 'FULL', 'CROSS', 'NATURAL'].includes(tokens[cursor].upper))
          ) {
            break;
          }
          cursor++;
        }
        if (cursor === condStart) {
          throw new Error('Expected condition after ON/USING in JOIN');
        }
      }
      continue;
    }
    throw new Error(`Unexpected token '${tok.raw}' in parenthesized table expression`);
  }
}

function validateTableRef(tokens, startIdx, cteNames, depth, refCounter) {
  const t0 = tokens[startIdx];
  if (!t0) {
    throw new Error('Expected table reference after FROM/JOIN');
  }
  refCounter.count++;
  if (refCounter.count > MAX_TABLE_REFS) {
    throw new Error(`Query exceeds maximum allowed table references (${MAX_TABLE_REFS})`);
  }

  if (t0.type === 'word' && t0.upper === 'LATERAL') {
    throw new Error('LATERAL table references are forbidden in Data Lake queries');
  }

  if (t0.value === '(') {
    const closeIdx = findMatchingParen(tokens, startIdx);
    const inner = tokens.slice(startIdx + 1, closeIdx);
    if (inner.length === 0) {
      throw new Error('Empty parenthesized subquery or table expression in Data Lake query');
    }
    if (isQueryStart(inner)) {
      validateQueryTokens(inner, cteNames, depth + 1, refCounter);
    } else {
      validateParenthesizedJoinExpr(inner, cteNames, depth + 1, refCounter);
    }
    return advanceOptionalAliasAndColumns(tokens, closeIdx + 1);
  }

  if (t0.type === 'string') {
    throw new Error(`Query cannot reference file or string literal source ${t0.raw}`);
  }
  if (t0.type !== 'word' && t0.type !== 'ident') {
    throw new Error(`Invalid table reference '${t0.raw}' in Data Lake query`);
  }
  if (tokens[startIdx + 1]?.value === '(') {
    throw new Error(`Table-valued function calls ('${t0.value}(...)') are forbidden in Data Lake queries`);
  }
  if (tokens[startIdx + 1]?.value === '.') {
    throw new Error(`Qualified table references ('${t0.value}.*') are not permitted in Data Lake queries`);
  }
  const lowerName = t0.value.toLowerCase();
  if (!ALLOWED_DATALAKE_TABLES.has(lowerName) && !cteNames.has(lowerName)) {
    throw new Error(`Access to table '${t0.value}' is forbidden; only 'security_events' is allowed`);
  }
  return advanceOptionalAliasAndColumns(tokens, startIdx + 1);
}

function validateQueryTokens(tokens, outerCtes = new Set(), depth = 0, refCounter = { count: 0 }) {
  if (depth > MAX_QUERY_DEPTH) {
    throw new Error(`Data Lake SQL query nesting exceeds maximum allowed depth (${MAX_QUERY_DEPTH})`);
  }
  if (!tokens || tokens.length === 0) {
    throw new Error('Data Lake query cannot be empty');
  }

  // Unwrap redundant outer parentheses: e.g. ((SELECT * FROM security_events))
  if (tokens[0].value === '(') {
    const closeIdx = findMatchingParen(tokens, 0);
    if (closeIdx === tokens.length - 1) {
      return validateQueryTokens(tokens.slice(1, closeIdx), outerCtes, depth + 1, refCounter);
    }
  }

  const first = tokens[0];
  if (first.type !== 'word' || (first.upper !== 'SELECT' && first.upper !== 'WITH')) {
    throw new Error('Only read-only SELECT or WITH queries are permitted against the Security Data Lake');
  }

  const localCtes = new Set(outerCtes);
  let mainIdx = 0;

  // Parse and recursively validate CTEs introduced by leading WITH clause
  if (first.upper === 'WITH') {
    let idx = 1;
    if (tokens[idx]?.type === 'word' && tokens[idx].upper === 'RECURSIVE') {
      throw new Error('Recursive CTEs (WITH RECURSIVE) are forbidden in Data Lake queries');
    }
    while (idx < tokens.length) {
      const nameTok = tokens[idx];
      if (!nameTok || (nameTok.type !== 'word' && nameTok.type !== 'ident')) {
        throw new Error('Invalid CTE definition in WITH clause');
      }
      idx++;
      if (tokens[idx]?.value === '(') {
        const colClose = findMatchingParen(tokens, idx);
        idx = colClose + 1;
      }
      if (tokens[idx]?.type !== 'word' || tokens[idx].upper !== 'AS') {
        throw new Error(`Expected AS in CTE '${nameTok.value}'`);
      }
      idx++;
      if (tokens[idx]?.type === 'word' && tokens[idx].upper === 'NOT') idx++;
      if (tokens[idx]?.type === 'word' && tokens[idx].upper === 'MATERIALIZED') idx++;

      if (tokens[idx]?.value !== '(') {
        throw new Error(`Expected parenthesized SELECT body for CTE '${nameTok.value}'`);
      }
      const bodyClose = findMatchingParen(tokens, idx);
      const bodyTokens = tokens.slice(idx + 1, bodyClose);
      // Validate CTE body BEFORE adding its own name to localCtes (prevents implicit self-recursion)
      validateQueryTokens(bodyTokens, localCtes, depth + 1, refCounter);
      localCtes.add(nameTok.value.toLowerCase());
      idx = bodyClose + 1;

      if (tokens[idx]?.value === ',') {
        idx++;
        continue;
      }
      break;
    }
    mainIdx = idx;
    if (mainIdx >= tokens.length) {
      throw new Error('WITH clause must be followed by a SELECT statement');
    }
  }

  // Validate main SELECT (and any UNION/INTERSECT/EXCEPT branches)
  if (tokens[mainIdx]?.value === '(') {
    const closeIdx = findMatchingParen(tokens, mainIdx);
    validateQueryTokens(tokens.slice(mainIdx + 1, closeIdx), localCtes, depth + 1, refCounter);
    mainIdx = closeIdx + 1;
  } else if (tokens[mainIdx]?.type !== 'word' || tokens[mainIdx].upper !== 'SELECT') {
    throw new Error('Only read-only SELECT or WITH queries are permitted against the Security Data Lake');
  }

  for (let idx = mainIdx; idx < tokens.length; idx++) {
    const tok = tokens[idx];
    if (tok.value === '(') {
      const closeIdx = findMatchingParen(tokens, idx);
      const inner = tokens.slice(idx + 1, closeIdx);
      if (isQueryStart(inner)) {
        validateQueryTokens(inner, localCtes, depth + 1, refCounter);
      } else {
        scanExpressionsForSubqueries(inner, localCtes, depth + 1, refCounter);
      }
      idx = closeIdx;
      continue;
    }

    if (tok.type === 'word' && (tok.upper === 'UNION' || tok.upper === 'INTERSECT' || tok.upper === 'EXCEPT')) {
      let nextIdx = idx + 1;
      if (tokens[nextIdx]?.type === 'word' && (tokens[nextIdx].upper === 'ALL' || tokens[nextIdx].upper === 'DISTINCT')) {
        nextIdx++;
      }
      validateQueryTokens(tokens.slice(nextIdx), outerCtes, depth + 1, refCounter);
      break;
    }

    if (tok.type === 'word' && tok.upper === 'JOIN') {
      let cursor = validateTableRef(tokens, idx + 1, localCtes, depth, refCounter);
      while (tokens[cursor]?.value === ',') {
        cursor = validateTableRef(tokens, cursor + 1, localCtes, depth, refCounter);
      }
      idx = cursor - 1;
      continue;
    }

    if (tok.type === 'word' && tok.upper === 'FROM') {
      let cursor = validateTableRef(tokens, idx + 1, localCtes, depth, refCounter);
      while (tokens[cursor]?.value === ',') {
        cursor = validateTableRef(tokens, cursor + 1, localCtes, depth, refCounter);
      }
      idx = cursor - 1;
    }
  }
}

/**
 * Validate that a Data Lake SQL query is a single read-only SELECT/WITH statement
 * over the allowlisted security_events table.
 * @param {string} sql
 * @returns {string} Cleaned SQL string
 */
export function assertReadOnlyDataLakeSql(sql) {
  if (typeof sql !== 'string' || !sql.trim()) {
    throw new Error('Data Lake query must be a non-empty SQL string');
  }
  if (sql.length > MAX_DATALAKE_SQL_LENGTH) {
    throw new Error(`Data Lake query exceeds maximum allowed length (${MAX_DATALAKE_SQL_LENGTH} characters)`);
  }

  const tokens = tokenizeDataLakeSql(sql);

  // Strip optional trailing semicolons only; reject any embedded semicolons
  while (tokens.length > 0 && tokens[tokens.length - 1].value === ';') {
    tokens.pop();
  }
  if (tokens.length === 0 || tokens.some(t => t.value === ';')) {
    throw new Error('Data Lake queries must contain a single read-only SQL statement');
  }

  for (const tok of tokens) {
    if (isForbiddenToken(tok)) {
      throw new Error(`Query contains forbidden DDL, DML, or filesystem access keyword '${tok.value}'`);
    }
  }

  validateDangerousFunctionCalls(tokens);
  validateQueryTokens(tokens, new Set(), 0, { count: 0 });

  const lastToken = tokens[tokens.length - 1];
  return sql.slice(0, lastToken.end).trim();
}

function createReadOnlySqliteAuthorizer() {
  if (!sqliteConstants) return null;
  const { SQLITE_OK, SQLITE_DENY, SQLITE_SELECT, SQLITE_READ, SQLITE_FUNCTION } = sqliteConstants;
  return (action, arg1, arg2) => {
    if (action === SQLITE_SELECT) return SQLITE_OK;
    if (action === SQLITE_READ) {
      return arg1 === 'security_events' ? SQLITE_OK : SQLITE_DENY;
    }
    if (action === SQLITE_FUNCTION) {
      const fnName = String(arg2 || '').toLowerCase();
      return FORBIDDEN_SQLITE_FUNCTIONS.has(fnName) ? SQLITE_DENY : SQLITE_OK;
    }
    return SQLITE_DENY;
  };
}

/**
 * Execute an analytical SQL query across Data Lake events
 * @param {string} sql 
 * @param {Array<any>} [params=[]]
 * @param {Object} [options={}]
 * @returns {Array<Object>} Row results
 */
export async function queryDataLake(sql, params = [], options = {}) {
  const safeSql = assertReadOnlyDataLakeSql(sql);
  const safeParams = Array.isArray(params) ? params : [];
  if (safeParams.length > MAX_DATALAKE_PARAMS) {
    throw new Error(`Data Lake query parameter count exceeds maximum (${MAX_DATALAKE_PARAMS})`);
  }

  const requestedMax = Number(options?.maxRows);
  const rowCap = Number.isInteger(requestedMax) && requestedMax > 0
    ? Math.min(requestedMax, MAX_DATALAKE_ROWS)
    : MAX_DATALAKE_ROWS;

  const boundedSql = `SELECT * FROM (${safeSql}\n) AS _vigilante_dl_bounded LIMIT ${rowCap}`;
  const db = initDataLake();

  if (activeBackend === 'sqlite' && typeof db.setAuthorizer === 'function') {
    const authorizer = createReadOnlySqliteAuthorizer();
    if (authorizer) {
      db.setAuthorizer(authorizer);
    }
    try {
      const stmt = db.prepare(boundedSql);
      if (typeof stmt.iterate === 'function') {
        const rows = [];
        for (const row of stmt.iterate(...safeParams)) {
          rows.push(row);
          if (rows.length >= rowCap) break;
        }
        return rows;
      }
      const rows = stmt.all(...safeParams);
      return Array.isArray(rows) ? rows.slice(0, rowCap) : [];
    } finally {
      db.setAuthorizer(null);
    }
  }

  const stmt = db.prepare(boundedSql);
  // Awaited uniformly: the SQLite backend resolves synchronously, the
  // DuckDB backend returns a Promise.
  const rows = await stmt.all(...safeParams);
  return Array.isArray(rows) ? rows.slice(0, rowCap) : [];
}

/**
 * Perform a retrospective threat hunt across historical events matching CTI indicators
 * @param {Array<string|Object>} indicators List of IPs, domains, or hash strings
 * @returns {Array<Object>} Historical matches
 */
export async function runRetrospectiveThreatHunt(indicators = []) {
  const db = initDataLake();
  const matches = [];

  for (const item of indicators) {
    const val = typeof item === 'string' ? item : (item.ip || item.domain || item.hash || '');
    if (!val) continue;

    const query = `
      SELECT id, event_type, source_pod, source_ip, dest_ip, dest_port, severity, mitre_technique, indicator, timestamp
      FROM security_events
      WHERE source_ip = ? OR dest_ip = ? OR indicator LIKE ? ESCAPE '\\' OR raw_json LIKE ? ESCAPE '\\'
      ORDER BY timestamp DESC
      LIMIT 100
    `;

    // The indicator is matched literally: escape LIKE wildcards so an IOC
    // containing % or _ cannot over-match unrelated events.
    const likeVal = `%${String(val).replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_')}%`;
    const rows = await db.prepare(query).all(val, val, likeVal, likeVal);
    if (rows && rows.length > 0) {
      matches.push({
        indicator: val,
        matchCount: rows.length,
        firstSeen: rows[rows.length - 1].timestamp,
        lastSeen: rows[0].timestamp,
        affectedPods: Array.from(new Set(rows.map(r => r.source_pod).filter(Boolean))),
        events: rows
      });
    }
  }

  logger.info('DATALAKE', `Retrospective threat hunt completed: ${matches.length} matched indicators found.`);
  return matches;
}
