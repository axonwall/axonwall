import { createClient, type ClickHouseClient } from '@clickhouse/client';

let client: ClickHouseClient | null = null;

function getClient(): ClickHouseClient | null {
  if (!process.env.CLICKHOUSE_URL && process.env.NODE_ENV === 'production') {
    return null;
  }
  if (!client) {
    client = createClient({
      url: process.env.CLICKHOUSE_URL || 'http://127.0.0.1:8123',
      username: process.env.CLICKHOUSE_USER || 'admin',
      password: process.env.CLICKHOUSE_PASSWORD || 'axonwallclickhouse',
      database: process.env.CLICKHOUSE_DB || 'axonwall',
    });
  }
  return client;
}

export async function getTopFlows() {
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
