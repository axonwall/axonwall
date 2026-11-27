import http from 'node:http';
import https from 'node:https';
import { createClient, type ClickHouseClient } from '@clickhouse/client';
import type { DesiredState } from '@axonwall/lib/schemas';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { getDesiredStateInternal } from './desired-state-internal';
import { assertSafeOutboundUrl, createPinnedLookup } from './ssrf-guard';

async function createPinnedClickHouseClient(opts: {
  url: string;
  username: string;
  password: string;
  database: string;
}): Promise<ClickHouseClient> {
  const { url, addresses } = await assertSafeOutboundUrl(opts.url, {
    allowHttp: true,
    allowPrivate: true,
  });
  const isHttps = url.protocol === 'https:';
  const lookup = createPinnedLookup(addresses);
  const agent = isHttps ? new https.Agent({ lookup }) : new http.Agent({ lookup });

  // Reject 3xx HTTP redirects at the transport level to prevent SSRF redirect bypasses.
  const origAddRequest = (agent as any).addRequest.bind(agent);
  (agent as any).addRequest = (req: http.ClientRequest, reqOpts: unknown) => {
    req.once('response', (res: http.IncomingMessage) => {
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400) {
        res.resume();
        req.destroy(new Error(`ClickHouse HTTP redirect (${status}) blocked by SSRF policy`));
      }
    });
    return origAddRequest(req, reqOpts);
  };

  return createClient({
    url: url.toString(),
    username: opts.username,
    password: opts.password,
    database: opts.database,
    http_agent: agent,
    clickhouse_settings: {
      max_http_get_redirects: '0',
    },
  });
}

function buildStateClickHouseConfig(state?: DesiredState | null): {
  url: string;
  username: string;
  password: string;
  database: string;
  table: string;
} | null {
  const envUrl = process.env.CLICKHOUSE_URL?.trim();
  const envPass = process.env.CLICKHOUSE_PASSWORD;
  if (envUrl && envPass) {
    return {
      url: envUrl,
      username: process.env.CLICKHOUSE_USER?.trim() || 'admin',
      password: envPass,
      database: process.env.CLICKHOUSE_DB?.trim() || 'axonwall',
      table: process.env.CLICKHOUSE_NETFLOW_TABLE?.trim() || 'netflow_flows',
    };
  }
  const nfCh = state?.netflow?.storage?.clickhouse;
  if (nfCh?.enabled && nfCh.url?.trim()) {
    return {
      url: nfCh.url.trim(),
      username: nfCh.username?.trim() || 'admin',
      password: nfCh.password || '',
      database: nfCh.database?.trim() || 'axonwall',
      table: nfCh.table?.trim() || 'netflow_flows',
    };
  }
  const obsCh = state?.observability?.clickhouse;
  if (obsCh?.enabled && obsCh.url?.trim()) {
    return {
      url: obsCh.url.trim(),
      username: obsCh.username?.trim() || 'admin',
      password: obsCh.password || '',
      database: obsCh.database?.trim() || 'axonwall',
      table: 'netflow_flows',
    };
  }
  return null;
}

export interface DataLakeTableMetric {
  name: string;
  rows: number;
  bytes: number;
  compressedRatio: string;
}

export interface DataLakeMetricsSnapshot {
  configured: boolean;
  unavailable: boolean;
  reason?: string;
  tables: DataLakeTableMetric[];
  totalEvents24h: number;
  eventsPerSecond: number;
  storageUsedBytes: number;
  averageCompression: string;
}

export async function queryDataLakeMetrics(cfg?: {
  enabled?: boolean;
  url?: string;
  database?: string;
  username?: string;
  password?: string;
}): Promise<DataLakeMetricsSnapshot> {
  const session = await getSession();
  assertActionPermitted(session, 'readonly');

  const envUrl = process.env.CLICKHOUSE_URL?.trim();
  const envPass = process.env.CLICKHOUSE_PASSWORD;
  const useEnv = Boolean(envUrl && envPass);
  const useCfg = Boolean(cfg?.enabled && cfg?.url?.trim());

  if (!useEnv && !useCfg) {
    return {
      configured: false,
      unavailable: false,
      reason: 'ClickHouse Data Lake is not enabled or configured on this appliance.',
      tables: [],
      totalEvents24h: 0,
      eventsPerSecond: 0,
      storageUsedBytes: 0,
      averageCompression: 'N/A',
    };
  }

  const database = (useEnv ? process.env.CLICKHOUSE_DB : cfg?.database)?.trim() || 'axonwall';
  const targetUrl = useEnv ? envUrl! : cfg!.url!.trim();
  let ch: ClickHouseClient;
  try {
    ch = await createPinnedClickHouseClient({
      url: targetUrl,
      username: (useEnv ? process.env.CLICKHOUSE_USER?.trim() : cfg?.username?.trim()) || 'admin',
      password: (useEnv ? envPass : cfg?.password) || '',
      database,
    });
  } catch (err: any) {
    return {
      configured: true,
      unavailable: true,
      reason: err?.message || 'ClickHouse endpoint blocked by SSRF policy.',
      tables: [],
      totalEvents24h: 0,
      eventsPerSecond: 0,
      storageUsedBytes: 0,
      averageCompression: 'N/A',
    };
  }

  try {
    const result = await ch.query({
      query: `
        SELECT
          concat(database, '.', table) AS name,
          toUInt64(sum(rows)) AS rows,
          toUInt64(sum(bytes_on_disk)) AS bytes,
          toUInt64(sum(data_uncompressed_bytes)) AS uncompressed_bytes
        FROM system.parts
        WHERE active = 1 AND database = {db:String}
        GROUP BY database, table
        ORDER BY bytes DESC
        LIMIT 50
      `,
      query_params: { db: database },
      format: 'JSONEachRow',
    });
    const rawRows = (await result.json()) as Array<{
      name?: string;
      rows?: string | number;
      bytes?: string | number;
      uncompressed_bytes?: string | number;
    }>;

    let totalRows = 0;
    let totalBytes = 0;
    let totalUncompressed = 0;
    const tables: DataLakeTableMetric[] = rawRows.map((r) => {
      const rows = Number(r.rows || 0);
      const bytes = Number(r.bytes || 0);
      const uncompressed = Number(r.uncompressed_bytes || 0);
      totalRows += rows;
      totalBytes += bytes;
      totalUncompressed += uncompressed;
      const ratio = bytes > 0 && uncompressed > 0 ? `${(uncompressed / bytes).toFixed(1)}x` : 'N/A';
      return {
        name: String(r.name || ''),
        rows,
        bytes,
        compressedRatio: ratio,
      };
    });

    return {
      configured: true,
      unavailable: false,
      tables,
      totalEvents24h: totalRows,
      eventsPerSecond: totalRows > 0 ? Math.round((totalRows / 86400) * 10) / 10 : 0,
      storageUsedBytes: totalBytes,
      averageCompression:
        totalBytes > 0 && totalUncompressed > 0
          ? `${(totalUncompressed / totalBytes).toFixed(1)}x`
          : 'N/A',
    };
  } catch (err: any) {
    return {
      configured: true,
      unavailable: true,
      reason: err?.message || 'ClickHouse Data Lake unreachable or query failed.',
      tables: [],
      totalEvents24h: 0,
      eventsPerSecond: 0,
      storageUsedBytes: 0,
      averageCompression: 'N/A',
    };
  } finally {
    try {
      await ch.close();
    } catch {}
  }
}

export interface TopFlowRow {
  src_ip: string;
  dst_ip: string;
  protocol: number | string;
  app_name?: string;
  node_id?: string;
  node_name?: string;
  total_packets: number;
  total_bytes: number;
}

export async function getTopFlows(options?: {
  nodeId?: string;
  limit?: number;
  windowHours?: number;
}): Promise<TopFlowRow[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const hasEnv = Boolean(process.env.CLICKHOUSE_URL?.trim() && process.env.CLICKHOUSE_PASSWORD);
  const state = hasEnv ? null : await getDesiredStateInternal().catch(() => null);
  const resolved = buildStateClickHouseConfig(state);
  if (!resolved) {
    return [];
  }

  const limit = Math.max(1, Math.min(200, Math.floor(options?.limit ?? 10)));
  const windowHours = Math.max(1, Math.min(24 * 90, Math.floor(options?.windowHours ?? 24)));
  const nodeId = options?.nodeId?.trim() || '';
  let ch: ClickHouseClient;
  try {
    ch = await createPinnedClickHouseClient({
      url: resolved.url,
      username: resolved.username,
      password: resolved.password,
      database: resolved.database,
    });
  } catch (err) {
    console.error('ClickHouse SSRF guard blocked query:', err);
    return [];
  }
  const tableName = (resolved.table || 'netflow_flows').replace(/[^a-zA-Z0-9_]/g, '') || 'netflow_flows';

  try {
    try {
      const result = await ch.query({
        query: `
          SELECT
            src_ip,
            dst_ip,
            protocol,
            any(app_name) AS app_name,
            node_id,
            any(node_name) AS node_name,
            toUInt64(sum(packets)) AS total_packets,
            toUInt64(sum(bytes)) AS total_bytes
          FROM ${tableName}
          WHERE timestamp >= now() - INTERVAL {windowHours:UInt32} HOUR
            AND ({nodeId:String} = '' OR node_id = {nodeId:String} OR node_name = {nodeId:String})
          GROUP BY src_ip, dst_ip, protocol, node_id
          ORDER BY total_bytes DESC
          LIMIT {limit:UInt32}
        `,
        query_params: { windowHours, nodeId, limit },
        format: 'JSONEachRow',
      });
      return (await result.json()) as TopFlowRow[];
    } catch {
      if (nodeId) return [];
      const fallback = await ch.query({
        query: `
          SELECT src_ip, dst_ip, protocol, sum(packets) AS total_packets, sum(bytes) AS total_bytes
          FROM flows
          GROUP BY src_ip, dst_ip, protocol
          ORDER BY total_bytes DESC
          LIMIT {limit:UInt32}
        `,
        query_params: { limit },
        format: 'JSONEachRow',
      });
      return (await fallback.json()) as TopFlowRow[];
    }
  } catch (err) {
    console.error('ClickHouse query error:', err);
    return [];
  } finally {
    try {
      await ch.close();
    } catch {}
  }
}
