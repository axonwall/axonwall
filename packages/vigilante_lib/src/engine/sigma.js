/**
 * SIGMA-to-SQL Detection Transpiler & Automated Threat Hunting Engine
 * Converts vendor-agnostic SIGMA detection rules (YAML/JSON) into ANSI SQL
 * compatible with embedded node:sqlite and DuckDB Data Lake instances.
 */

import { queryDataLake } from './datalake.js';
import { logger } from '../utils/logger.js';

/**
 * Standard field mapping from common SIGMA field names to Vigilante security_events columns
 */
export const SIGMA_FIELD_MAPPINGS = {
  'destination.ip': 'dest_ip',
  'destinationip': 'dest_ip',
  'dest_ip': 'dest_ip',
  'dst_ip': 'dest_ip',
  'dst': 'dest_ip',
  'source.ip': 'source_ip',
  'sourceip': 'source_ip',
  'src_ip': 'source_ip',
  'src': 'source_ip',
  'destination.port': 'dest_port',
  'destinationport': 'dest_port',
  'dest_port': 'dest_port',
  'dst_port': 'dest_port',
  'event_type': 'event_type',
  'service': 'event_type',
  'product': 'event_type',
  'pod': 'source_pod',
  'source_pod': 'source_pod',
  'severity': 'severity',
  'level': 'severity',
  'indicator': 'indicator',
  'ioc': 'indicator',
  'mitre_technique': 'mitre_technique',
  'technique': 'mitre_technique'
};

/**
 * Parse simple SIGMA YAML or JSON content into a structured object
 * Supports basic YAML structures without external yaml dependencies
 * @param {string|Object} input
 * @returns {Object} Structured SIGMA rule definition
 */
const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function stripForbiddenKeys(val, seen = new WeakSet()) {
  if (val === null || typeof val !== 'object') return val;
  if (seen.has(val)) return val;
  seen.add(val);
  if (Array.isArray(val)) return val.map((item) => stripForbiddenKeys(item, seen));
  const clean = Object.create(null);
  for (const [k, v] of Object.entries(val)) {
    if (FORBIDDEN_OBJECT_KEYS.has(k)) continue;
    clean[k] = stripForbiddenKeys(v, seen);
  }
  return clean;
}

export function parseSigmaRule(input) {
  if (typeof input === 'object' && input !== null) {
    return stripForbiddenKeys(input);
  }

  if (typeof input !== 'string') {
    throw new Error('Invalid SIGMA input: expected string or object');
  }

  // Attempt standard JSON parse first
  try {
    return stripForbiddenKeys(JSON.parse(input));
  } catch {
    // Basic lightweight YAML line parser for key-value and detection mappings
    const rule = { detection: Object.create(null), logsource: Object.create(null), tags: [] };
    const lines = input.split(/\r?\n/);
    let currentSection = null;
    let currentSubSection = null;
    let listField = null; // detection field currently collecting '- item' list entries

    for (let rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      if (!rawLine.startsWith(' ') && !rawLine.startsWith('\t') && line.includes(':')) {
        const [k, ...v] = line.split(':');
        const key = k.trim();
        if (FORBIDDEN_OBJECT_KEYS.has(key)) continue;
        const val = v.join(':').trim();
        if (['detection', 'logsource', 'tags'].includes(key)) {
          currentSection = key;
          currentSubSection = null;
        } else {
          currentSection = null;
          rule[key] = val.replace(/^['"]|['"]$/g, '');
        }
      } else if (currentSection === 'tags' && line.startsWith('-')) {
        rule.tags.push(line.replace(/^-\s*/, '').replace(/^['"]|['"]$/g, ''));
      } else if (currentSection === 'detection') {
        if ((rawLine.startsWith('  ') || rawLine.startsWith('\t')) && !rawLine.startsWith('    ') && line.includes(':')) {
          const [k, ...v] = line.split(':');
          const subKey = k.trim();
          if (FORBIDDEN_OBJECT_KEYS.has(subKey)) continue;
          const subVal = v.join(':').trim();
          listField = null;
          if (subKey === 'condition') {
            rule.detection.condition = subVal.replace(/^['"]|['"]$/g, '');
            currentSubSection = null;
          } else {
            currentSubSection = subKey;
            rule.detection[currentSubSection] = subVal ? { _val: subVal.replace(/^['"]|['"]$/g, '') } : Object.create(null);
          }
        } else if (currentSubSection && listField && line.startsWith('-')) {
          // YAML list item under the current field: collect it instead of
          // dropping it (a field with list values previously collapsed to
          // an empty string and hunted for nothing).
          const item = line.replace(/^-\s*/, '').replace(/^['"]|['"]$/g, '');
          const cur = rule.detection[currentSubSection][listField];
          if (Array.isArray(cur)) cur.push(item);
          else rule.detection[currentSubSection][listField] = [item];
        } else if (currentSubSection && line.includes(':')) {
          const [k, ...v] = line.split(':');
          const field = k.trim().replace(/^-\s*/, '');
          if (FORBIDDEN_OBJECT_KEYS.has(field)) continue;
          const val = v.join(':').trim().replace(/^['"]|['"]$/g, '');
          rule.detection[currentSubSection][field] = val;
          listField = val === '' ? field : null;
        }
      }
    }

    if (!rule.title) rule.title = 'Untitled SIGMA Rule';
    if (!rule.detection.condition) rule.detection.condition = 'selection';
    return rule;
  }
}

/**
 * Transpile a single field and value into an SQL WHERE clause fragment
 * @param {string} field
 * @param {any} value
 * @returns {string}
 */
/** Quote a value as an SQL string literal (single quotes doubled). */
function quoteSqlString(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

/**
 * Escape a literal segment for use inside a LIKE pattern: the escape
 * character itself, then the two LIKE wildcards, so a literal % or _ in a
 * rule value matches only itself. Clauses using this must add ESCAPE '\'.
 */
function escapeLikeLiteral(segment) {
  return String(segment).replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
}

/**
 * Build a LIKE pattern from a Sigma value. In Sigma, `*` is the wildcard;
 * every other character is literal. Splitting on `*`, escaping each literal
 * segment, and joining with `%` preserves the intended matching while
 * making quote breakout and wildcard smuggling impossible.
 */
function sigmaLikePattern(value, { contains = false, startswith = false, endswith = false } = {}) {
  const segments = String(value).split('*').map(escapeLikeLiteral);
  let pattern = segments.join('%');
  if (contains) pattern = `%${pattern}%`;
  if (startswith) pattern = `${pattern}%`;
  if (endswith) pattern = `%${pattern}`;
  return pattern;
}

function transpileFieldClause(field, value) {
  let [fieldName, ...modifiers] = field.split('|');
  const normalizedCol = SIGMA_FIELD_MAPPINGS[fieldName.toLowerCase()];
  const isDirectCol = Boolean(normalizedCol);
  const targetCol = isDirectCol ? normalizedCol : 'raw_json';

  const stringVal = String(value);
  const hasContains = modifiers.includes('contains');
  const hasStartswith = modifiers.includes('startswith');
  const hasEndswith = modifiers.includes('endswith');

  if (targetCol === 'raw_json') {
    // If not a direct column, search within raw_json or indicator. The
    // field name and value are rule-supplied data: both are LIKE-escaped
    // and the finished patterns are quoted as SQL literals, so neither
    // can break out of the string and alter the WHERE clause.
    const fieldPattern = escapeLikeLiteral(fieldName);
    const valuePattern = sigmaLikePattern(stringVal, { contains: true });
    return `(raw_json LIKE ${quoteSqlString(`%"${fieldPattern}":"${valuePattern}"%`)} ESCAPE '\\' OR indicator LIKE ${quoteSqlString(valuePattern)} ESCAPE '\\' OR raw_json LIKE ${quoteSqlString(valuePattern)} ESCAPE '\\')`;
  }

  if (hasContains || stringVal.includes('*')) {
    const pattern = sigmaLikePattern(stringVal, { contains: hasContains });
    return `${targetCol} LIKE ${quoteSqlString(pattern)} ESCAPE '\\'`;
  }

  if (hasStartswith) {
    return `${targetCol} LIKE ${quoteSqlString(sigmaLikePattern(stringVal, { startswith: true }))} ESCAPE '\\'`;
  }

  if (hasEndswith) {
    return `${targetCol} LIKE ${quoteSqlString(sigmaLikePattern(stringVal, { endswith: true }))} ESCAPE '\\'`;
  }

  if (typeof value === 'number' || (!isNaN(Number(value)) && normalizedCol === 'dest_port')) {
    return `${targetCol} = ${Number(value)}`;
  }

  return `${targetCol} = ${quoteSqlString(stringVal)}`;
}

/**
 * Transpile a SIGMA detection section selection into an SQL predicate
 * @param {Object} selection
 * @returns {string}
 */
function transpileSelection(selection) {
  if (!selection || typeof selection !== 'object') return '1=1';

  const clauses = [];
  for (const [key, val] of Object.entries(selection)) {
    if (key === '_val') continue;
    if (Array.isArray(val)) {
      const orClauses = val.map(v => transpileFieldClause(key, v));
      clauses.push(`(${orClauses.join(' OR ')})`);
    } else {
      clauses.push(transpileFieldClause(key, val));
    }
  }

  return clauses.length > 0 ? clauses.join(' AND ') : '1=1';
}

/**
 * Transpile a complete SIGMA rule into an ANSI SQL query over security_events
 * @param {Object|string} ruleInput
 * @param {Object} [options={}]
 * @returns {{ sql: string, title: string, level: string, technique: string|null }}
 */
export function transpileSigmaToSql(ruleInput, options = {}) {
  const rule = parseSigmaRule(ruleInput);
  // The table name is interpolated into the SQL raw, so it must be a plain
  // identifier — anything else is rejected rather than sanitized silently.
  const tableName = options.table || 'security_events';
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tableName)) {
    throw new Error(`Invalid table name '${tableName}': expected a plain SQL identifier`);
  }

  const detection = rule.detection || {};
  const condition = (detection.condition || 'selection').trim();

  // Transpile named selections into a prototype-free map
  const selectionClauses = Object.create(null);
  for (const [name, def] of Object.entries(detection)) {
    if (name === 'condition' || FORBIDDEN_OBJECT_KEYS.has(name)) continue;
    selectionClauses[name] = transpileSelection(def);
  }

  // Strictly tokenize & compile boolean condition AST in a single pass so no
  // SQL keywords, string literals, subqueries, or condition-overwriting
  // selection values can be injected.
  const tokens = [];
  const tokenRe = /\s+|(\(|\)|\b1\s+of\s+(?:selection\*|[a-zA-Z0-9_]+)\b|\ball\s+of\s+(?:selection\*|[a-zA-Z0-9_]+)\b|[a-zA-Z_][a-zA-Z0-9_]*)/gi;
  let lastIdx = 0;
  let match;
  while ((match = tokenRe.exec(condition)) !== null) {
    if (match.index !== lastIdx) {
      throw new Error(`Invalid SIGMA condition token near '${condition.slice(lastIdx, match.index)}'`);
    }
    lastIdx = tokenRe.lastIndex;
    if (match[1]) {
      tokens.push(match[1]);
    }
  }
  if (lastIdx !== condition.length || tokens.length === 0) {
    throw new Error(`Invalid SIGMA condition '${condition}': unexpected character sequence`);
  }

  let parens = 0;
  const compiledTokens = tokens.map((tok) => {
    const lower = tok.toLowerCase();
    if (tok === '(') {
      parens++;
      return '(';
    }
    if (tok === ')') {
      parens--;
      if (parens < 0) throw new Error('Invalid SIGMA condition: unbalanced parentheses');
      return ')';
    }
    if (lower === 'and') return 'AND';
    if (lower === 'or') return 'OR';
    if (lower === 'not') return 'NOT';

    const ofMatch = /^(1|all)\s+of\s+(selection\*|[a-zA-Z0-9_]+)$/i.exec(tok);
    if (ofMatch) {
      const joiner = ofMatch[1].toLowerCase() === '1' ? 'OR' : 'AND';
      const prefix = ofMatch[2].endsWith('*') ? ofMatch[2].slice(0, -1) : ofMatch[2];
      const matching = Object.keys(selectionClauses).filter((k) => k.startsWith(prefix));
      const block = matching.length > 0
        ? matching.map((k) => `(${selectionClauses[k]})`).join(` ${joiner} `)
        : '1=1';
      return `(${block})`;
    }

    if (Object.prototype.hasOwnProperty.call(selectionClauses, tok)) {
      return `(${selectionClauses[tok]})`;
    }
    throw new Error(`Unknown identifier '${tok}' in SIGMA condition`);
  });
  if (parens !== 0) {
    throw new Error('Invalid SIGMA condition: unclosed parenthesis');
  }

  const sqlCondition = compiledTokens.join(' ');

  const technique = (rule.tags || []).find(t => /^attack\.t\d{4}/i.test(t))?.replace(/^attack\./i, '').toUpperCase() || null;

  const sql = `SELECT * FROM ${tableName} WHERE ${sqlCondition} ORDER BY timestamp DESC`;

  return {
    sql,
    title: rule.title || 'SIGMA Rule Detection',
    level: (rule.level || 'medium').toUpperCase(),
    technique
  };
}

/**
 * Execute a batch of SIGMA rules against the active Security Data Lake
 * @param {Array<Object|string>} sigmaRules
 * @returns {Array<Object>} Matched threat hunt findings
 */
export async function runSigmaThreatHunt(sigmaRules = []) {
  const matches = [];
  const rules = Array.isArray(sigmaRules) ? sigmaRules : (sigmaRules ? [sigmaRules] : []);

  for (const item of rules) {
    try {
      const transpiled = transpileSigmaToSql(item);
      const rows = await queryDataLake(transpiled.sql);

      if (rows && rows.length > 0) {
        matches.push({
          ruleTitle: transpiled.title,
          level: transpiled.level,
          technique: transpiled.technique,
          matchCount: rows.length,
          firstSeen: rows[rows.length - 1].timestamp,
          lastSeen: rows[0].timestamp,
          affectedPods: Array.from(new Set(rows.map(r => r.source_pod).filter(Boolean))),
          events: rows
        });
      }
    } catch (err) {
      logger.warn('SIGMA', `Failed to execute rule: ${err.message}`);
    }
  }

  return matches;
}

/**
 * Generate candidate threat hunting hypothesis and SIGMA/SQL query for a MITRE technique
 * @param {string} techniqueId e.g. 'T1059.004', 'T1021.002', 'T1071.001'
 * @returns {Object}
 */
export function generateHypothesisForTechnique(techniqueId) {
  const tid = techniqueId.toUpperCase();

  const presets = {
    'T1059.004': {
      title: 'Suspicious Unix Shell Spawn in Container',
      technique: 'T1059.004',
      description: 'Detects execution of interactive bash/sh shells inside non-administrative container workloads.',
      hypothesis: 'Adversary leveraged an RCE vulnerability to spawn a reverse shell in a web application pod.',
      sigma: {
        title: 'Shell Spawn in Web Container',
        level: 'high',
        tags: ['attack.t1059.004'],
        detection: {
          selection: {
            indicator: '*sh*',
            severity: 'CRITICAL'
          },
          condition: 'selection'
        }
      }
    },
    'T1021.002': {
      title: 'Lateral SMB Traffic Between Workload Pods',
      technique: 'T1021.002',
      description: 'Detects East-West SMB (port 445) communication across non-storage pods.',
      hypothesis: 'Compromised identity attempting lateral file share access or PsExec-style lateral execution.',
      sigma: {
        title: 'Anomalous Lateral SMB Connections',
        level: 'high',
        tags: ['attack.t1021.002'],
        detection: {
          selection: {
            'destination.port': 445
          },
          condition: 'selection'
        }
      }
    },
    'T1071.001': {
      title: 'C2 Web Beaconing to Untrusted IPs',
      technique: 'T1071.001',
      description: 'Detects outbound HTTPS/HTTP egress to low-reputation or newly discovered IP addresses.',
      hypothesis: 'Malware establishing command and control channel to external host.',
      sigma: {
        title: 'C2 Web Protocol Beaconing',
        level: 'critical',
        tags: ['attack.t1071.001'],
        detection: {
          selection: {
            'destination.port': 443,
            severity: 'CRITICAL'
          },
          condition: 'selection'
        }
      }
    }
  };

  const selected = presets[tid] || {
    title: `Generic Threat Hunt for ${tid}`,
    technique: tid,
    description: `Automated hypothesis for technique ${tid}`,
    hypothesis: `Telemetry reveals behaviors matching ${tid}`,
    sigma: {
      title: `Rule for ${tid}`,
      level: 'medium',
      tags: [`attack.${tid.toLowerCase()}`],
      detection: {
        selection: {
          mitre_technique: tid
        },
        condition: 'selection'
      }
    }
  };

  const transpiled = transpileSigmaToSql(selected.sigma);
  return {
    ...selected,
    sql: transpiled.sql
  };
}

export {
  generateHypothesisForTechnique as generateSigmaHypothesis
};
