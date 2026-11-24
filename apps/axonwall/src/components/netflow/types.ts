export type {
  NetFlowAlertSnapshot,
  NetFlowBaselineSummarySnapshot,
  NetFlowExporterSnapshot,
  NetFlowFleetPeerErrorSnapshot,
  NetFlowGeoArcSnapshot,
  NetFlowHeatmapMatrixSnapshot,
  NetFlowListenerStatusSnapshot,
  NetFlowPercentileRowSnapshot,
  NetFlowQueryRecordSnapshot,
  NetFlowQueryResponseSnapshot,
  NetFlowReportResponseSnapshot,
  NetFlowSessionRecordSnapshot,
  NetFlowStatusSnapshot,
  NetFlowTemplateSnapshot,
  NetFlowTopEntrySnapshot,
} from '@/server/agent';

export const FQL_PRESETS: Array<{ label: string; fql: string }> = [
  { label: 'HTTPS / TLS', fql: 'dst_port=443 and proto=tcp' },
  { label: 'DNS Queries', fql: 'dst_port=53' },
  { label: 'Egress Internet', fql: 'direction=egress' },
  { label: 'Threat IOC Hits', fql: 'threat!=""' },
  { label: 'Heavy (> 1 MB)', fql: 'bytes>1MB' },
  { label: 'SYN Scans', fql: 'proto=tcp and tcp_flags~SYN and bytes<2KB' },
  { label: 'K3s Workloads', fql: 'k3s_ns!=""' },
  { label: 'NAT Translated', fql: 'post_nat_src!=""' },
  { label: 'TCP Retransmits', fql: 'retransmits>0' },
];

export const TIME_RANGE_OPTIONS: Array<{ label: string; minutes: number; id: string }> = [
  { id: '5m', label: '5m', minutes: 5 },
  { id: '15m', label: '15m', minutes: 15 },
  { id: '1h', label: '1h', minutes: 60 },
  { id: '6h', label: '6h', minutes: 360 },
  { id: '24h', label: '24h', minutes: 1440 },
  { id: '7d', label: '7d', minutes: 10080 },
  { id: '30d', label: '30d', minutes: 43200 },
];

export const SERIES_COLORS = [
  '#38bdf8',
  '#10b981',
  '#a78bfa',
  '#f59e0b',
  '#fb7185',
  '#22d3ee',
];
