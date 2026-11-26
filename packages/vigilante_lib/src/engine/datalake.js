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
try {
  const sqlite = require('node:sqlite');
  DatabaseSync = sqlite.DatabaseSync || null;
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

const FORBIDDEN_DATALAKE_KEYWORDS = new Set([
  'ATTACH', 'DETACH', 'PRAGMA', 'COPY', 'EXPORT', 'IMPORT', 'INSTALL', 'LOAD',
  'SET', 'RESET', 'CALL', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER',
  'CREATE', 'REPLACE', 'VACUUM', 'MERGE', 'TRUNCATE', 'GRANT', 'REVOKE',
  'READ_TEXT', 'READ_BLOB', 'READ_CSV', 'READ_CSV_AUTO', 'READ_JSON',
  'READ_JSON_AUTO', 'READ_PARQUET', 'READ_XLSX', 'SNIFF_CSV', 'PARQUET_SCAN',
  'SQLITE_MASTER', 'SQLITE_TEMP_MASTER', 'SQLITE_SCHEMA', 'SQLITE_TEMP_SCHEMA',
  'GLOB', 'HTTPFS', 'LOAD_EXTENSION', 'EXEC', 'EXECUTE'
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

  const tokens = tokenizeDataLakeSql(sql);

  // Strip optional trailing semicolons only; reject any embedded semicolons
  while (tokens.length > 0 && tokens[tokens.length - 1].value === ';') {
    tokens.pop();
  }
  if (tokens.length === 0 || tokens.some(t => t.value === ';')) {
    throw new Error('Data Lake queries must contain a single read-only SQL statement');
  }

  const first = tokens[0];
  if (first.type !== 'word' || (first.upper !== 'SELECT' && first.upper !== 'WITH')) {
    throw new Error('Only read-only SELECT or WITH queries are permitted against the Security Data Lake');
  }

  for (const tok of tokens) {
    if (isForbiddenToken(tok)) {
      throw new Error(`Query contains forbidden DDL, DML, or filesystem access keyword '${tok.value}'`);
    }
  }

  // Collect CTE names introduced by leading WITH clause
  const cteNames = new Set();
  if (first.upper === 'WITH') {
    let idx = 1;
    if (tokens[idx]?.type === 'word' && tokens[idx].upper === 'RECURSIVE') idx++;
    while (idx < tokens.length) {
      const nameTok = tokens[idx];
      if (!nameTok || (nameTok.type !== 'word' && nameTok.type !== 'ident')) break;
      cteNames.add(nameTok.value.toLowerCase());
      idx++;
      if (tokens[idx]?.value === '(') {
        let depth = 1;
        idx++;
        while (idx < tokens.length && depth > 0) {
          if (tokens[idx].value === '(') depth++;
          else if (tokens[idx].value === ')') depth--;
          idx++;
        }
      }
      if (tokens[idx]?.type === 'word' && tokens[idx].upper === 'AS') {
        idx++;
        // Optional MATERIALIZED / NOT MATERIALIZED
        if (tokens[idx]?.type === 'word' && tokens[idx].upper === 'NOT') idx++;
        if (tokens[idx]?.type === 'word' && tokens[idx].upper === 'MATERIALIZED') idx++;
      }
      if (tokens[idx]?.value === '(') {
        let depth = 1;
        idx++;
        while (idx < tokens.length && depth > 0) {
          if (tokens[idx].value === '(') depth++;
          else if (tokens[idx].value === ')') depth--;
          idx++;
        }
      }
      if (tokens[idx]?.value === ',') {
        idx++;
        continue;
      }
      break;
    }
  }

  // Enforce FROM / JOIN table target allowlist
  const validateTableRef = (startIdx) => {
    const t0 = tokens[startIdx];
    if (!t0) {
      throw new Error('Expected table reference after FROM/JOIN');
    }
    if (t0.value === '(') {
      return startIdx + 1;
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
    // Advance past table name and optional alias (AS alias / alias)
    let cursor = startIdx + 1;
    if (tokens[cursor]?.type === 'word' && tokens[cursor].upper === 'AS') {
      cursor += 2;
    } else if (
      tokens[cursor] &&
      (tokens[cursor].type === 'word' || tokens[cursor].type === 'ident') &&
      !CLAUSE_STOP_KEYWORDS.has(tokens[cursor].upper)
    ) {
      cursor += 1;
    }
    return cursor;
  };

  for (let idx = 0; idx < tokens.length; idx++) {
    const tok = tokens[idx];
    if (tok.type === 'word' && tok.upper === 'JOIN') {
      validateTableRef(idx + 1);
    } else if (tok.type === 'word' && tok.upper === 'FROM') {
      // Distinguish EXTRACT(x FROM y) or SUBSTRING(... FROM ...) inside function parens?
      // Inside SELECT list, EXTRACT(YEAR FROM timestamp) uses FROM followed by a column/expr, not a table!
      // Check if directly preceded by '(' + non-SELECT expression (not a subquery).
      // Better: scan back to matching '(' or statement start — if inside parens whose opening wasn't followed by SELECT/WITH, skip!
      let parenDepth = 0;
      let isExtractOrSubstr = false;
      for (let b = idx - 1; b >= 0; b--) {
        if (tokens[b].value === ')') parenDepth++;
        else if (tokens[b].value === '(') {
          if (parenDepth === 0) {
            const nextInParen = tokens[b + 1];
            const prevFn = tokens[b - 1];
            if (
              prevFn?.type === 'word' &&
              nextInParen?.upper !== 'SELECT' &&
              nextInParen?.upper !== 'WITH'
            ) {
              isExtractOrSubstr = true;
            }
            break;
          }
          parenDepth--;
        }
      }
      if (isExtractOrSubstr) continue;

      let cursor = validateTableRef(idx + 1);
      while (tokens[cursor]?.value === ',') {
        cursor = validateTableRef(cursor + 1);
      }
    }
  }

  const lastToken = tokens[tokens.length - 1];
  return sql.slice(0, lastToken.end).trim();
}

/**
 * Execute an analytical SQL query across Data Lake events
 * @param {string} sql 
 * @param {Array<any>} [params=[]]
 * @returns {Array<Object>} Row results
 */
export async function queryDataLake(sql, params = []) {
  const safeSql = assertReadOnlyDataLakeSql(sql);
  const db = initDataLake();
  const stmt = db.prepare(safeSql);
  // Awaited uniformly: the SQLite backend resolves synchronously, the
  // DuckDB backend returns a Promise.
  return await stmt.all(...params);
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
