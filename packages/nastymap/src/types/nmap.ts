/**
 * NastyMap Nmap Type Definitions
 * Complete type mapping for Nmap XML output, network topology, GeoIP data, and scan diffing.
 */

export interface NmapAddress {
  addr: string;
  addrtype: 'ipv4' | 'ipv6' | 'mac';
  vendor?: string;
}

export interface NmapHostname {
  name: string;
  type: string;
}

export interface NmapScript {
  id: string;
  output: string;
  elements?: Record<string, string>;
}

export interface NmapService {
  name: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  method?: string;
  conf?: string;
  cpe?: string[];
  tunnel?: string;
  proto?: string;
  rpcnum?: string;
  lowver?: string;
  highver?: string;
  ostype?: string;
  devicetype?: string;
  servicefp?: string;
}

export interface NmapPort {
  portid: number;
  protocol: 'tcp' | 'udp' | 'sctp' | 'ip';
  state: 'open' | 'closed' | 'filtered' | 'unfiltered' | 'open|filtered' | 'closed|filtered';
  reason?: string;
  reason_ttl?: number;
  service?: NmapService;
  scripts?: NmapScript[];
}

export interface NmapOsClass {
  type?: string;
  vendor?: string;
  osfamily?: string;
  osgen?: string;
  accuracy?: number;
  cpe?: string[];
}

export interface NmapOsMatch {
  name: string;
  accuracy: number;
  line?: string;
  osclasses: NmapOsClass[];
}

export interface NmapOs {
  portused?: Array<{ state: string; proto: string; portid: number }>;
  osmatches: NmapOsMatch[];
  osfingerprint?: string;
}

export interface NmapHop {
  ttl: number;
  ipaddr: string;
  rtt?: number; // Round-trip time in milliseconds
  host?: string;
}

export interface NmapTrace {
  port?: number;
  proto?: string;
  hops: NmapHop[];
}

export interface NmapUptime {
  seconds: number;
  lastboot?: string;
}

export interface NmapTimes {
  srtt: number; // Smoothed round trip time (microseconds)
  rttvar: number; // Variance
  to: number; // Timeout
}

export interface NmapGeoLocation {
  ip: string;
  city?: string;
  region?: string;
  country?: string;
  countryCode?: string;
  latitude: number;
  longitude: number;
  isp?: string;
  asn?: string;
  org?: string;
  timezone?: string;
  isPrivate?: boolean;
}

export interface NmapHost {
  id: string; // generated unique id e.g. ip or host id
  status: {
    state: 'up' | 'down' | 'unknown' | 'filtered';
    reason?: string;
    reason_ttl?: number;
  };
  addresses: NmapAddress[];
  hostnames: NmapHostname[];
  ports: NmapPort[];
  os?: NmapOs;
  distance?: number; // hop count
  trace?: NmapTrace;
  uptime?: NmapUptime;
  times?: NmapTimes;
  hostscripts?: NmapScript[];
  comments?: string;
  tags?: string[];
  geolocation?: NmapGeoLocation;
  // convenient computed getters
  ipv4?: string;
  ipv6?: string;
  mac?: string;
  primaryHostname?: string;
  primaryOs?: string;
  osFamily?: string;
  deviceType?: string;
  openPortCount?: number;
  latencyMs?: number;
  customData?: Record<string, any>;
  isFlagged?: boolean;
  isQuarantined?: boolean;
}

export interface NmapScanInfo {
  type: string;
  protocol: string;
  numservices: number;
  services: string;
}

export interface NmapRunStats {
  finished: {
    time: number;
    timestr?: string;
    summary?: string;
    elapsed?: number;
    exit?: string;
  };
  hosts: {
    up: number;
    down: number;
    total: number;
  };
}

export interface NmapRun {
  scanner: string;
  args: string;
  start: number;
  startstr: string;
  version: string;
  xmloutputversion: string;
  scaninfo?: NmapScanInfo[];
  verbose?: { level: number };
  debugging?: { level: number };
  hosts: NmapHost[];
  runstats: NmapRunStats;
  rawXml?: string;
}

// Topology & Visualization Types
export type TopologyLayoutType = 'force' | 'traceroute' | 'radial' | 'subnet' | 'circular';

export interface TopologyNode {
  id: string;
  label: string;
  ip: string;
  hostname?: string;
  nodeType: 'scanner' | 'intermediate_hop' | 'gateway' | 'router' | 'host' | 'switch';
  status: 'up' | 'down' | 'unknown' | 'filtered';
  osFamily: string;
  osName: string;
  deviceType: string;
  openPorts: number[];
  openPortDetails: NmapPort[];
  latencyMs?: number;
  hopsAway: number;
  subnet?: string;
  hostRef?: NmapHost;
  geolocation?: NmapGeoLocation;
  // Graph simulation coordinates
  x: number;
  y: number;
  vx?: number;
  vy?: number;
  radius: number;
  color?: string;
  icon?: string;
  isPinned?: boolean;
  customData?: Record<string, any>;
  isFlagged?: boolean;
  isQuarantined?: boolean;
}

export interface TopologyLink {
  id: string;
  source: string | TopologyNode;
  target: string | TopologyNode;
  rtt?: number; // latency ms
  type: 'traceroute' | 'subnet' | 'gateway' | 'direct';
  ttl?: number;
  label?: string;
}

export interface TopologyGraph {
  nodes: TopologyNode[];
  links: TopologyLink[];
  scannerNode: TopologyNode;
  subnets: string[];
}

// Scan Diff Types
export interface HostPortDiff {
  portid: number;
  protocol: string;
  changeType: 'added' | 'removed' | 'modified' | 'unchanged';
  oldPort?: NmapPort;
  newPort?: NmapPort;
}

export interface HostDiff {
  ip: string;
  hostname?: string;
  changeType: 'added' | 'removed' | 'modified' | 'unchanged';
  statusChanged?: boolean;
  oldStatus?: string;
  newStatus?: string;
  osChanged?: boolean;
  oldOs?: string;
  newOs?: string;
  portDiffs: HostPortDiff[];
  latencyDeltaMs?: number;
  oldHost?: NmapHost;
  newHost?: NmapHost;
}

export interface NmapScanDiff {
  oldScan: NmapRun;
  newScan: NmapRun;
  addedHosts: HostDiff[];
  removedHosts: HostDiff[];
  modifiedHosts: HostDiff[];
  unchangedHosts: HostDiff[];
  summary: {
    totalHostsA: number;
    totalHostsB: number;
    hostsAdded: number;
    hostsRemoved: number;
    hostsModified: number;
    portsAdded: number;
    portsRemoved: number;
    portsModified: number;
  };
}

export interface FilterOptions {
  searchQuery: string;
  osFamily?: string;
  portFilter?: number[];
  onlyOpenPorts?: boolean;
  onlyUpHosts?: boolean;
  maxLatencyMs?: number;
  deviceType?: string;
  subnetFilter?: string;
  hasVulnerability?: boolean;
  tagFilter?: string;
}

export interface DetailLevelSettings {
  showLabels: boolean;
  labelType: 'ip' | 'hostname' | 'both';
  showOsIcons: boolean;
  showPortBadges: boolean;
  showLatency: boolean;
  showIntermediateHops: boolean;
  showUptime: boolean;
  showSubnetHulls: boolean;
  nodeSize: 'compact' | 'standard' | 'large';
}

// Extensibility Types
export interface HostActionContext {
  node?: TopologyNode;
  updateHost: (updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => void;
  notify?: (message: string, type?: 'info' | 'success' | 'warning' | 'error') => void;
  scan?: NmapRun;
  closeDrawer?: () => void;
}

export interface HostAction {
  id: string;
  label: string;
  icon?: any;
  shortcut?: string; // e.g. 'd', 'Shift+D', 'r', 'q'
  variant?: 'default' | 'primary' | 'danger' | 'warning' | 'success' | 'outline';
  tooltip?: string;
  description?: string;
  onClick: (
    host: NmapHost,
    context: HostActionContext
  ) => void | Promise<void | Partial<NmapHost> | NmapHost>;
  isDisabled?: (host: NmapHost) => boolean;
  isVisible?: (host: NmapHost) => boolean;
}

export interface CustomDrawerTab {
  id: string;
  label: string;
  icon?: any;
  badge?: (host: NmapHost) => string | number | undefined;
  render: (
    host: NmapHost,
    updateHost: (updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => void
  ) => any;
}

