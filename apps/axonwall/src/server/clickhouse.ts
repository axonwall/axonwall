import { createClient } from '@clickhouse/client';

const client = createClient({
  host: process.env.CLICKHOUSE_URL || 'http://127.0.0.1:8123',
  username: process.env.CLICKHOUSE_USER || 'admin',
  password: process.env.CLICKHOUSE_PASSWORD || 'axonwallclickhouse',
  database: process.env.CLICKHOUSE_DB || 'axonwall',
});

export async function getTopFlows() {
  try {
    const result = await client.query({
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
