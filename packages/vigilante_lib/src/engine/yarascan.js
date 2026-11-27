/**
 * VIGILANTE In-Memory Process YARA & Cobalt Strike Configuration Extractor
 * Zero-dependency pure JavaScript YARA-like byte/regex scanning engine,
 * process memory triage, and Cobalt Strike / C2 beacon config extractor.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

/**
 * Cobalt Strike Configuration Setting Types (TLV)
 */
export const CS_SETTINGS_MAP = {
  1: { name: 'BEACON_TYPE', type: 'short' },
  2: { name: 'PORT', type: 'short' },
  3: { name: 'SLEEP_TIME', type: 'int' },
  4: { name: 'MAX_GET_SIZE', type: 'int' },
  5: { name: 'JITTER', type: 'short' },
  6: { name: 'MAX_DNS', type: 'short' },
  7: { name: 'C2_PUBLIC_KEY', type: 'bytes' },
  8: { name: 'C2_SERVERS', type: 'string' },
  9: { name: 'USER_AGENT', type: 'string' },
  10: { name: 'POST_URI', type: 'string' },
  11: { name: 'MFRAG_SIZE', type: 'int' },
  14: { name: 'SPAWNTO_X86', type: 'string' },
  15: { name: 'SPAWNTO_X64', type: 'string' },
  26: { name: 'WATERMARK', type: 'int' },
  37: { name: 'WATERMARK_4X', type: 'int' },
  54: { name: 'HOST_HEADER', type: 'string' }
};

/**
 * Compile a YARA-like rule specification
 * Supports string definition or structured object:
 * {
 *   name: 'rule_name',
 *   meta: { description: '...', author: '...', mitre: 'T1055' },
 *   strings: [
 *     { id: '$str1', type: 'text', value: 'malware', nocase: true, wide: false },
 *     { id: '$hex1', type: 'hex', value: '4d 5a ?? 00' },
 *     { id: '$re1', type: 'regex', value: 'beacon\\.[a-z]{3}' }
 *   ],
 *   condition: '$str1 and ($hex1 or $re1)' // or 'any of them', 'all of them'
 * }
 * @param {Object|string} ruleDef
 * @returns {Object} Compiled rule
 */
function assertSafeRegexPattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    throw new Error('YARA regex pattern must be a non-empty string');
  }
  if (pattern.length > 512) {
    throw new Error(`YARA regex pattern exceeds maximum length (${pattern.length} > 512)`);
  }
  let inClass = false;
  const groupHasQuantifier = [];
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '\\') {
      i++;
      continue;
    }
    if (ch === '[' && !inClass) {
      inClass = true;
      continue;
    }
    if (ch === ']' && inClass) {
      inClass = false;
      continue;
    }
    if (inClass) continue;
    if (ch === '(') {
      groupHasQuantifier.push(false);
    } else if (ch === ')') {
      const innerQuantified = groupHasQuantifier.pop() || false;
      const next = pattern[i + 1];
      const nextIsQuant = next === '+' || next === '*' || next === '?' || next === '{';
      if (innerQuantified && nextIsQuant) {
        throw new Error('Unsafe YARA regex pattern: nested quantifiers are disallowed to prevent ReDoS');
      }
      if (groupHasQuantifier.length > 0 && (innerQuantified || nextIsQuant)) {
        groupHasQuantifier[groupHasQuantifier.length - 1] = true;
      }
    } else if (ch === '+' || ch === '*' || ch === '{') {
      if (ch === '{') {
        const closeBrace = pattern.indexOf('}', i + 1);
        if (closeBrace !== -1) {
          const inner = pattern.slice(i + 1, closeBrace);
          const nums = inner.split(',').map(s => Number(s.trim())).filter(n => !Number.isNaN(n));
          if (nums.some(n => n > 1000)) {
            throw new Error('Unsafe YARA regex pattern: repetition count exceeds limit (1000)');
          }
          i = closeBrace;
        }
      }
      if (groupHasQuantifier.length > 0) {
        groupHasQuantifier[groupHasQuantifier.length - 1] = true;
      }
    }
  }
}

export function compileYaraRule(ruleDef) {
  if (typeof ruleDef === 'string') {
    return parseYaraTextRule(ruleDef);
  }

  const compiledStrings = (ruleDef.strings || []).map(s => {
    let matcher;
    if (s.type === 'hex') {
      // Convert hex pattern with ?? wildcards into regex
      const hexParts = s.value.trim().split(/\s+/);
      const regexParts = hexParts.map(part => {
        if (part === '??' || part === '?') return '[\\s\\S]';
        const byteVal = parseInt(part, 16);
        return '\\x' + byteVal.toString(16).padStart(2, '0');
      });
      matcher = new RegExp(regexParts.join(''), 'g');
    } else if (s.type === 'regex') {
      assertSafeRegexPattern(s.value);
      const flags = s.nocase ? 'gi' : 'g';
      matcher = new RegExp(s.value, flags);
    } else {
      // Text string
      if (s.wide) {
        // UTF-16LE encoding (every ascii char followed by 0x00)
        const wideBytes = [];
        for (let i = 0; i < s.value.length; i++) {
          const code = s.value.charCodeAt(i);
          wideBytes.push('\\x' + code.toString(16).padStart(2, '0') + '\\x00');
        }
        matcher = new RegExp(wideBytes.join(''), s.nocase ? 'gi' : 'g');
      } else {
        const escaped = s.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        matcher = new RegExp(escaped, s.nocase ? 'gi' : 'g');
      }
    }

    return {
      id: s.id || `$s_${Math.random().toString(36).substring(2, 7)}`,
      type: s.type || 'text',
      original: s.value,
      matcher
    };
  });

  return {
    name: ruleDef.name || 'unnamed_rule',
    meta: ruleDef.meta || {},
    strings: compiledStrings,
    condition: ruleDef.condition || 'any of them'
  };
}

/**
 * Basic parser for text-based YARA rule blocks
 */
function parseYaraTextRule(text) {
  const nameMatch = text.match(/rule\s+([A-Za-z0-9_]+)/);
  const name = nameMatch ? nameMatch[1] : 'parsed_rule';

  const strings = [];
  const stringsBlockMatch = text.match(/strings:\s*([\s\S]*?)(?:condition:|$)/i);
  if (stringsBlockMatch) {
    const lines = stringsBlockMatch[1].split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//')) continue;
      // $var = "text" [nocase]
      const textMatch = trimmed.match(/(\$[A-Za-z0-9_]+)\s*=\s*"([^"]+)"(?:\s*(nocase|wide))*/i);
      if (textMatch) {
        strings.push({
          id: textMatch[1],
          type: 'text',
          value: textMatch[2],
          nocase: trimmed.includes('nocase'),
          wide: trimmed.includes('wide')
        });
        continue;
      }
      // $hex = { 4D 5A ?? 00 }
      const hexMatch = trimmed.match(/(\$[A-Za-z0-9_]+)\s*=\s*\{\s*([0-9a-fA-F\s?]+)\s*\}/);
      if (hexMatch) {
        strings.push({
          id: hexMatch[1],
          type: 'hex',
          value: hexMatch[2]
        });
        continue;
      }
    }
  }

  const condMatch = text.match(/condition:\s*([\s\S]*?)\s*\}\s*$/i) || text.match(/condition:\s*([\s\S]+?)$/i);
  const condition = condMatch ? condMatch[1].replace(/\}\s*$/, '').trim() : 'any of them';

  return compileYaraRule({ name, meta: {}, strings, condition });
}

/**
 * Scan a binary buffer or string with compiled YARA rules
 * @param {Buffer|Uint8Array|string} inputBuffer
 * @param {Array<Object>|Object} compiledRules
 * @returns {Array<Object>} Matched rules
 */
export function scanBufferWithRules(inputBuffer, compiledRules = []) {
  if (!inputBuffer) return [];
  const rules = Array.isArray(compiledRules) ? compiledRules : [compiledRules];
  const bufStr = Buffer.isBuffer(inputBuffer) 
    ? inputBuffer.toString('binary') 
    : (typeof inputBuffer === 'string' ? inputBuffer : Buffer.from(inputBuffer).toString('binary'));

  const matches = [];

  for (const rule of rules) {
    const stringMatches = {};
    const matchOffsets = [];

    // Evaluate each string in the rule
    for (const strDef of rule.strings) {
      strDef.matcher.lastIndex = 0;
      let m;
      let count = 0;
      while ((m = strDef.matcher.exec(bufStr)) !== null) {
        count++;
        matchOffsets.push({
          id: strDef.id,
          offset: m.index,
          length: m[0].length,
          type: strDef.type
        });
        // Avoid infinite loop on zero-length matches
        if (m.index === strDef.matcher.lastIndex) strDef.matcher.lastIndex++;
      }
      stringMatches[strDef.id] = count;
    }

    // Evaluate condition
    const isMatched = evaluateRuleCondition(rule.condition, stringMatches, rule.strings);
    if (isMatched) {
      matches.push({
        rule: rule.name,
        meta: rule.meta,
        matchesCount: matchOffsets.length,
        matchOffsets,
        matchedStringIds: Object.keys(stringMatches).filter(k => stringMatches[k] > 0)
      });
    }
  }

  return matches;
}

/**
 * Evaluate boolean condition expression against string match counts without dynamic eval
 */
function evaluateRuleCondition(condition, stringMatches, strings) {
  const cond = String(condition || '').trim();
  const lowerCond = cond.toLowerCase();

  if (!cond || lowerCond === 'any of them') {
    return Object.values(stringMatches).some(c => c > 0);
  }
  if (lowerCond === 'all of them') {
    return strings.length > 0 && strings.every(s => (stringMatches[s.id] || 0) > 0);
  }

  const tokens = [];
  const tokenRe = /\s+|(\(|\)|&&|\|\||!|\$[A-Za-z0-9_]+|\b(?:and|or|not|true|false|any\s+of\s+them|all\s+of\s+them)\b)/gi;
  let lastIdx = 0;
  let m;
  while ((m = tokenRe.exec(cond)) !== null) {
    if (m.index !== lastIdx) {
      throw new Error(`Invalid YARA condition syntax near '${cond.slice(lastIdx, m.index)}'`);
    }
    lastIdx = tokenRe.lastIndex;
    if (m[1]) tokens.push(m[1]);
  }
  if (lastIdx !== cond.length || tokens.length === 0) {
    throw new Error(`Invalid YARA condition expression '${cond}'`);
  }

  let pos = 0;
  const peek = () => tokens[pos];
  const consume = () => tokens[pos++];

  const parseOr = () => {
    let left = parseAnd();
    while (peek() && (peek().toLowerCase() === 'or' || peek() === '||')) {
      consume();
      const right = parseAnd();
      left = left || right;
    }
    return left;
  };

  const parseAnd = () => {
    let left = parseNot();
    while (peek() && (peek().toLowerCase() === 'and' || peek() === '&&')) {
      consume();
      const right = parseNot();
      left = left && right;
    }
    return left;
  };

  const parseNot = () => {
    if (peek() && (peek().toLowerCase() === 'not' || peek() === '!')) {
      consume();
      return !parseNot();
    }
    return parsePrimary();
  };

  const parsePrimary = () => {
    const tok = consume();
    if (!tok) throw new Error('Unexpected end of YARA condition expression');
    if (tok === '(') {
      const val = parseOr();
      if (consume() !== ')') throw new Error('Unclosed parenthesis in YARA condition');
      return val;
    }
    const low = tok.toLowerCase();
    if (low === 'true') return true;
    if (low === 'false') return false;
    if (/^any\s+of\s+them$/i.test(tok)) return Object.values(stringMatches).some(c => c > 0);
    if (/^all\s+of\s+them$/i.test(tok)) return strings.length > 0 && strings.every(s => (stringMatches[s.id] || 0) > 0);
    if (tok.startsWith('$')) {
      return (stringMatches[tok] || 0) > 0;
    }
    throw new Error(`Unsupported YARA condition token '${tok}'`);
  };

  const value = parseOr();
  if (pos !== tokens.length) {
    throw new Error(`Unexpected token '${tokens[pos]}' in YARA condition`);
  }
  return Boolean(value);
}

/**
 * Extract and decrypt Cobalt Strike Beacon configuration blocks from memory buffer
 * @param {Buffer|Uint8Array} inputBuffer
 * @returns {Object} Extracted configuration
 */
export function extractCobaltStrikeConfig(inputBuffer) {
  if (!inputBuffer) return { detected: false, reason: 'Empty buffer' };

  const buf = Buffer.isBuffer(inputBuffer) ? inputBuffer : Buffer.from(inputBuffer);
  // Candidate XOR keys commonly used by Cobalt Strike
  const xorKeys = [0x2e, 0x69];

  for (const key of xorKeys) {
    const config = scanForCsConfigWithKey(buf, key);
    if (config && config.settings && Object.keys(config.settings).length >= 2) {
      return {
        detected: true,
        xorKey: key,
        version: key === 0x2e ? '3.x' : '4.x',
        settings: config.settings,
        rawMatches: Object.keys(config.settings).length
      };
    }
  }

  return {
    detected: false,
    xorKey: null,
    version: null,
    settings: {},
    rawMatches: 0
  };
}

/**
 * Scan for CS configuration block using a specific 1-byte XOR key
 */
function scanForCsConfigWithKey(buf, key) {
  // Setting 1 (BEACON_TYPE: type=0x0001, valType=0x0001 short)
  const targetPrefix = Buffer.from([0x00 ^ key, 0x01 ^ key, 0x00 ^ key, 0x01 ^ key]);
  let offset = buf.indexOf(targetPrefix);

  if (offset === -1) {
    // Setting 2 (PORT: type=0x0002, valType=0x0001 short)
    const portPrefix = Buffer.from([0x00 ^ key, 0x02 ^ key, 0x00 ^ key, 0x01 ^ key]);
    offset = buf.indexOf(portPrefix);
  }

  if (offset === -1) return null;

  // Attempt to decode TLV items starting at offset
  const settings = {};
  let cur = offset;
  const maxScan = Math.min(buf.length, offset + 4096);

  while (cur + 6 <= maxScan) {
    const type = ((buf[cur] ^ key) << 8) | (buf[cur + 1] ^ key);
    const valType = ((buf[cur + 2] ^ key) << 8) | (buf[cur + 3] ^ key);
    cur += 4;

    if (type === 0 || type > 100) break; // End of config block or invalid

    const meta = CS_SETTINGS_MAP[type];
    const settingName = meta?.name || `UNKNOWN_${type}`;

    if (valType === 1) {
      // Short (2 bytes)
      if (cur + 2 > maxScan) break;
      const val = ((buf[cur] ^ key) << 8) | (buf[cur + 1] ^ key);
      settings[settingName] = val;
      cur += 2;
    } else if (valType === 2) {
      // Int (4 bytes)
      if (cur + 4 > maxScan) break;
      const val = ((buf[cur] ^ key) << 24) |
                  ((buf[cur + 1] ^ key) << 16) |
                  ((buf[cur + 2] ^ key) << 8) |
                  (buf[cur + 3] ^ key);
      settings[settingName] = val;
      cur += 4;
    } else if (valType === 3) {
      // String or bytes (length is next 2 bytes)
      if (cur + 2 > maxScan) break;
      const strLen = ((buf[cur] ^ key) << 8) | (buf[cur + 1] ^ key);
      cur += 2;
      if (strLen > 1024 || cur + strLen > maxScan) break;

      const strBytes = [];
      for (let i = 0; i < strLen; i++) {
        const b = buf[cur + i] ^ key;
        if (b === 0) break; // Null terminator
        strBytes.push(String.fromCharCode(b));
      }
      settings[settingName] = strBytes.join('');
      cur += strLen;
    } else {
      break;
    }
  }

  return { settings };
}

const CONTAINER_CGROUP_RE = /(kubepods|docker|containerd|cri-o|crio|podman|libpod|lxc|ecs|fargate)/i;

/**
 * Validate that a target PID is safe to inspect from live /proc (forbids MCP server's
 * own PID, host PID 1 / parent PID, and any non-container host-sensitive process).
 * @param {number|string} pid
 * @param {Object} [options={}]
 * @returns {Promise<number>} Validated PID
 */
export async function assertSafeLiveContainerPid(pid, options = {}) {
  const procRoot = options.procRoot || '/proc';
  const allowMockMissing = Boolean(options.allowMockMissing);
  const numPid = Number(pid);

  if (!Number.isInteger(numPid) || numPid <= 0) {
    throw new Error(`Invalid process ID '${pid}': expected a positive integer`);
  }
  if (numPid === process.pid) {
    throw new Error(
      `Forbidden process ID '${numPid}': reading the Vigilante/MCP server's own process (/proc/${numPid}) is prohibited`
    );
  }
  if (numPid === 1 || (Number.isInteger(process.ppid) && process.ppid > 1 && numPid === process.ppid)) {
    throw new Error(
      `Forbidden process ID '${numPid}': reading host init or parent process (/proc/${numPid}) is prohibited`
    );
  }

  const isLiveHostProc = path.resolve(procRoot) === '/proc';
  if (!isLiveHostProc) {
    return numPid;
  }

  const procDir = path.join(procRoot, String(numPid));
  let dirExists = false;
  try {
    await fs.access(procDir);
    dirExists = true;
  } catch {
    dirExists = false;
  }

  if (!dirExists) {
    if (allowMockMissing) {
      return numPid;
    }
    throw new Error(`Forbidden or unavailable process ID '${numPid}': /proc/${numPid} does not exist`);
  }

  let inContainerCgroup = false;
  try {
    const cgroup = await fs.readFile(path.join(procDir, 'cgroup'), 'utf8');
    if (CONTAINER_CGROUP_RE.test(cgroup)) {
      inContainerCgroup = true;
    }
  } catch {
    // Unreadable cgroup cannot prove container membership
  }

  let inDistinctPidNamespace = false;
  try {
    const [selfNs, targetNs] = await Promise.all([
      fs.readlink('/proc/self/ns/pid'),
      fs.readlink(path.join(procDir, 'ns', 'pid'))
    ]);
    if (selfNs && targetNs && selfNs !== targetNs) {
      inDistinctPidNamespace = true;
    }
  } catch {
    // Unreadable PID namespace (e.g. privileged host daemon) fails closed
  }

  if (!inContainerCgroup && !inDistinctPidNamespace) {
    throw new Error(
      `Forbidden process ID '${numPid}': target is a non-container or host-sensitive process (container isolation required)`
    );
  }

  return numPid;
}

/**
 * Scan process memory given a PID or simulated memory chunks
 * @param {number|string} pid
 * @param {Array<Object>} rules
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Process memory scan result
 */
export async function scanProcessMemory(pid, rules = [], options = {}) {
  const numPid = Number(pid);
  if (!Number.isInteger(numPid) || numPid <= 0) {
    throw new Error(`Invalid process ID '${pid}': expected a positive integer`);
  }

  const result = {
    pid: numPid,
    timestamp: new Date().toISOString(),
    yaraMatches: [],
    c2Config: null,
    segmentsScanned: 0,
    status: 'CLEAN'
  };

  let bufferToScan = options.memoryBuffer || null;
  const maxTotalBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : 64 * 1024 * 1024;
  const maxRegionBytes = 4 * 1024 * 1024;

  // Attempt to read readable /proc/<pid>/maps regions from /proc/<pid>/mem
  if (!bufferToScan) {
    const procBase = options.procRoot || '/proc';
    await assertSafeLiveContainerPid(numPid, { procRoot: procBase, allowMockMissing: false });
    const memPath = path.join(procBase, String(numPid), 'mem');
    const mapsPath = path.join(procBase, String(numPid), 'maps');
    if (fsSync.existsSync(mapsPath)) {
      if (fsSync.lstatSync(mapsPath).isSymbolicLink()) {
        throw new Error(`Refusing symlinked maps file '${mapsPath}'`);
      }
      const mapsContent = await fs.readFile(mapsPath, 'utf8');
      const regions = [];
      for (const line of mapsContent.split(/\r?\n/)) {
        const match = /^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+[0-9a-f]+\s+[0-9a-f:]+\s+\d+\s*(.*)$/i.exec(line.trim());
        if (!match) continue;
        const start = BigInt(`0x${match[1]}`);
        const end = BigInt(`0x${match[2]}`);
        const perms = match[3];
        const pathname = (match[4] || '').trim();
        if (!perms.startsWith('r')) continue;
        if (pathname === '[vvar]' || pathname === '[vsyscall]') continue;
        if (end <= start || start > BigInt(Number.MAX_SAFE_INTEGER)) continue;
        const size = Number(end - start > BigInt(maxRegionBytes) ? BigInt(maxRegionBytes) : end - start);
        if (size > 0) {
          regions.push({ start: Number(start), size });
        }
      }

      if (regions.length > 0 && fsSync.existsSync(memPath)) {
        if (fsSync.lstatSync(memPath).isSymbolicLink()) {
          throw new Error(`Refusing symlinked mem file '${memPath}'`);
        }
        const chunks = [];
        let totalRead = 0;
        const fh = await fs.open(memPath, 'r');
        try {
          for (const reg of regions) {
            if (totalRead >= maxTotalBytes) break;
            const toRead = Math.min(reg.size, maxTotalBytes - totalRead);
            const buf = Buffer.allocUnsafe(toRead);
            try {
              const { bytesRead } = await fh.read(buf, 0, toRead, reg.start);
              if (bytesRead > 0) {
                chunks.push(bytesRead === toRead ? buf : buf.subarray(0, bytesRead));
                totalRead += bytesRead;
                result.segmentsScanned++;
              }
            } catch {
              // Individual unmapped/guarded pages can fail EIO while others remain readable
            }
          }
        } finally {
          await fh.close();
        }
        if (chunks.length > 0) {
          bufferToScan = Buffer.concat(chunks);
        }
      }
    }
  } else {
    result.segmentsScanned = 1;
  }

  if (bufferToScan) {
    if (result.segmentsScanned === 0) result.segmentsScanned = 1;
    // 1. Evaluate YARA rules
    result.yaraMatches = scanBufferWithRules(bufferToScan, rules);

    // 2. Extract Cobalt Strike configuration
    result.c2Config = extractCobaltStrikeConfig(bufferToScan);

    if (result.c2Config.detected || result.yaraMatches.length > 0) {
      result.status = 'SUSPICIOUS_THREAT_DETECTED';
    }
  }

  return result;
}

/**
 * Generate human-readable and structured YARA report
 * @param {Object} results
 * @returns {Object} Report
 */
export function generateYaraMemoryReport(results = {}) {
  const hasThreat = results.status === 'SUSPICIOUS_THREAT_DETECTED' || 
                    (results.yaraMatches && results.yaraMatches.length > 0) || 
                    (results.c2Config && results.c2Config.detected);

  return {
    summary: {
      pid: results.pid || null,
      status: hasThreat ? 'CRITICAL_MALWARE_ACTIVE' : 'CLEAN',
      yaraRulesMatched: results.yaraMatches?.length || 0,
      c2Extracted: results.c2Config?.detected || false
    },
    yaraMatches: results.yaraMatches || [],
    c2Configuration: results.c2Config || { detected: false },
    timestamp: results.timestamp || new Date().toISOString()
  };
}
