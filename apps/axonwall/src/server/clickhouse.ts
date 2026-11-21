import { createClient, type ClickHouseClient } from '@clickhouse/client';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';

let client: ClickHouseClient | null = null;

function getClient(): ClickHouseClient | null {
  if (!process.env.CLICKHOUSE_URL || !process.env.CLICKHOUSE_PASSWORD) {
    return null;
  }
  if (!client) {
    client = createClient({
      url: process.env.CLICKHOUSE_URL,
      username: process.env.CLICKHOUSE_USER || 'admin',
      password: process.env.CLICKHOUSE_PASSWORD,
      database: process.env.CLICKHOUSE_DB || 'axonwall',
    });
  }
  return client;
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
  const ch = useEnv
    ? getClient()!
    : createClient({
        url: cfg!.url!.trim(),
        username: cfg?.username?.trim() || 'admin',
        password: cfg?.password || '',
        database,
      });

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
    if (!useEnv) {
      try {
        await ch.close();
      } catch {}
    }
  }
}

export async function getTopFlows() {
  const session = await getSession();
  assertActionPermitted(session);

  const ch = getClient();
  if (!ch) {
    return [];
  }
  try {
    const result = await ch.query({
      query: `
        SELECT src_ip, dst_ip, protocol, sum(packets) as total_packets, sum(bytes) as total_bytes
        FROM flows
        GROUP BY src_ip, dst_ip, protocol
        ORDER BY total_bytes DESC
        LIMIT 10
      `,
      format: 'JSONEachRow',
    });
    return await result.json();
  } catch (err) {
    console.error('ClickHouse query error:', err);
    return [];
  }
}
