package engine

type NetFlowTlsConfigPayload struct {
	UseHaPki           bool   `json:"useHaPki"`
	RequireClientCert  bool   `json:"requireClientCert"`
	CertPath           string `json:"certPath,omitempty"`
	KeyPath            string `json:"keyPath,omitempty"`
	CAPath             string `json:"caPath,omitempty"`
	ServerName         string `json:"serverName,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
}

type NetFlowListenerPayload struct {
	ID                   string                   `json:"id"`
	Name                 string                   `json:"name"`
	Enabled              bool                     `json:"enabled"`
	Protocol             string                   `json:"protocol"`  // auto | netflow | ipfix | sflow
	Transport            string                   `json:"transport"` // udp | tcp | tls
	BindAddress          string                   `json:"bindAddress"`
	Port                 int                      `json:"port"`
	SocketRecvBufferKB   int                      `json:"socketRecvBufferKB"`
	Workers              int                      `json:"workers"`
	AllowedExporters     []string                 `json:"allowedExporters"`
	DropUnknownTemplates bool                     `json:"dropUnknownTemplates"`
	TLS                  *NetFlowTlsConfigPayload `json:"tls,omitempty"`
}

type NetFlowExporterProfilePayload struct {
	ID                   string            `json:"id"`
	IP                   string            `json:"ip"`
	Name                 string            `json:"name"`
	Site                 string            `json:"site,omitempty"`
	Vendor               string            `json:"vendor"`
	SamplingRateOverride int               `json:"samplingRateOverride"`
	IfIndexAliases       map[string]string `json:"ifIndexAliases"`
	Enabled              bool              `json:"enabled"`
	ExpectedFpsMin       float64           `json:"expectedFpsMin"`
}

type NetFlowSelfExportTargetPayload struct {
	ID                  string                   `json:"id"`
	Name                string                   `json:"name"`
	Enabled             bool                     `json:"enabled"`
	Version             string                   `json:"version"` // ipfix | netflow9
	Host                string                   `json:"host"`
	Port                int                      `json:"port"`
	Transport           string                   `json:"transport"` // udp | tcp | tls
	Interfaces          []string                 `json:"interfaces"`
	ActiveTimeoutSec    int                      `json:"activeTimeoutSec"`
	InactiveTimeoutSec  int                      `json:"inactiveTimeoutSec"`
	TemplateRefreshSec  int                      `json:"templateRefreshSec"`
	SamplingRate        int                      `json:"samplingRate"`
	ObservationDomainID uint32                   `json:"observationDomainId"`
	TLS                 *NetFlowTlsConfigPayload `json:"tls,omitempty"`
}

type NetFlowMetadataSyncPayload struct {
	Enabled     bool   `json:"enabled"`
	TargetURL   string `json:"targetUrl,omitempty"`
	APIToken    string `json:"apiToken,omitempty"`
	IntervalSec int    `json:"intervalSec"`
}

type NetFlowSelfExportPayload struct {
	Enabled      bool                             `json:"enabled"`
	Targets      []NetFlowSelfExportTargetPayload `json:"targets"`
	MetadataSync *NetFlowMetadataSyncPayload      `json:"metadataSync,omitempty"`
}

type NetFlowReplicatorTargetPayload struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	DestinationHost string   `json:"destinationHost"`
	DestinationPort int      `json:"destinationPort"`
	SpoofSourceIP   bool     `json:"spoofSourceIp"`
	FilterExporters []string `json:"filterExporters"`
	FilterProtocols []string `json:"filterProtocols"`
	RateLimitPps    int      `json:"rateLimitPps"`
}

type NetFlowReplicatorPayload struct {
	Enabled bool                             `json:"enabled"`
	Targets []NetFlowReplicatorTargetPayload `json:"targets"`
}

type NetFlowClickHousePayload struct {
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"`
	Database  string `json:"database"`
	Table     string `json:"table"`
	Username  string `json:"username"`
	Password  string `json:"password,omitempty"`
	BatchSize int    `json:"batchSize"`
	TTLDays   int    `json:"ttlDays"`
}

type NetFlowStoragePayload struct {
	Mode            string                   `json:"mode"` // local | clickhouse | hybrid
	DataDir         string                   `json:"dataDir"`
	RetentionHours  int                      `json:"retentionHours"`
	MaxDiskMB       int                      `json:"maxDiskMB"`
	HotRingSize     int                      `json:"hotRingSize"`
	FlushIntervalSec int                     `json:"flushIntervalSec"`
	Compression     string                   `json:"compression"` // zstd | gzip | none
	RollupIntervals []string                 `json:"rollupIntervals"`
	ClickHouse      NetFlowClickHousePayload `json:"clickhouse"`
}

type NetFlowEnrichmentPayload struct {
	ReverseDNS              bool              `json:"reverseDns"`
	DNSCacheTTLSec          int               `json:"dnsCacheTtlSec"`
	KeaDHCPLeases           bool              `json:"keaDhcpLeases"`
	UnboundOverrides        bool              `json:"unboundOverrides"`
	LibreNMSIfNames         bool              `json:"librenmsIfNames"`
	NetBoxInventory         bool              `json:"netboxInventory"`
	K3sPodServiceTagging    bool              `json:"k3sPodServiceTagging"`
	FrrBgpLookup            bool              `json:"frrBgpLookup"`
	NatConntrackCorrelation bool              `json:"natConntrackCorrelation"`
	GeoIPAsn                bool              `json:"geoipAsn"`
	GeoIPCityDBPath         string            `json:"geoipCityDbPath"`
	GeoIPAsnDBPath          string            `json:"geoipAsnDbPath"`
	GeoIPAutoUpdate         bool              `json:"geoipAutoUpdate"`
	GeoIPUpdateIntervalHrs  int               `json:"geoipUpdateIntervalHours"`
	GeoIPCityDownloadURL    string            `json:"geoipCityDownloadUrl,omitempty"`
	GeoIPAsnDownloadURL     string            `json:"geoipAsnDownloadUrl,omitempty"`
	ThreatIntelMatch        bool              `json:"threatIntelMatch"`
	CustomPortApps          map[string]string `json:"customPortApps"`
	InternalCidrs           []string          `json:"internalCidrs"`
}

type NetFlowReportingPayload struct {
	Enabled        bool   `json:"enabled"`
	IntervalHours  int    `json:"intervalHours"`
	Format         string `json:"format"`  // json | csv | markdown
	GroupBy        string `json:"groupBy"` // interface | exporter | vlan | subnet
	RangeDays      int    `json:"rangeDays"`
	RetentionCount int    `json:"retentionCount"`
	WebhookURL     string `json:"webhookUrl,omitempty"`
}

type NetFlowAlertRulePayload struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Enabled              bool     `json:"enabled"`
	Kind                 string   `json:"kind"`
	Severity             string   `json:"severity"`
	FQLFilter            string   `json:"fqlFilter,omitempty"`
	Threshold            float64  `json:"threshold"`
	WindowSec            int      `json:"windowSec"`
	CooldownSec          int      `json:"cooldownSec"`
	Actions              []string `json:"actions"`
	XdpBlockTTLSec       int      `json:"xdpBlockTtlSec"`
	RemoteEdgeMitigation bool     `json:"remoteEdgeMitigation,omitempty"`
	WebhookURL           string   `json:"webhookUrl,omitempty"`
}

type NetFlowAlertingPayload struct {
	Enabled bool                      `json:"enabled"`
	Rules   []NetFlowAlertRulePayload `json:"rules"`
}

type NetFlowTopologyOverlayConfigPayload struct {
	Enabled   bool `json:"enabled"`
	WindowSec int  `json:"windowSec"`
}

type NetFlowConfigPayload struct {
	Enabled          bool                                `json:"enabled"`
	Mode             string                              `json:"mode,omitempty"`   // collector | exporter | both
	NodeID           string                              `json:"nodeId,omitempty"`
	Listeners        []NetFlowListenerPayload            `json:"listeners"`
	ExporterProfiles []NetFlowExporterProfilePayload     `json:"exporterProfiles"`
	SelfExport       NetFlowSelfExportPayload            `json:"selfExport"`
	Replicator       NetFlowReplicatorPayload            `json:"replicator"`
	Storage          NetFlowStoragePayload               `json:"storage"`
	Enrichment       NetFlowEnrichmentPayload            `json:"enrichment"`
	Alerting         NetFlowAlertingPayload              `json:"alerting"`
	TopologyOverlay  NetFlowTopologyOverlayConfigPayload `json:"topologyOverlay"`
	Reporting        NetFlowReportingPayload             `json:"reporting"`
}

type NetFlowInterfaceHint struct {
	Name        string `json:"name"`
	Device      string `json:"device"`
	Role        string `json:"role,omitempty"`
	IPv4Address string `json:"ipv4Address,omitempty"`
}

type NetFlowStaticHostEntry struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Source   string `json:"source"`
}

type NetFlowThreatEntry struct {
	Alias string `json:"alias"`
	Entry string `json:"entry"`
}

type NetFlowK3sCidrs struct {
	PodCIDR     string `json:"podCidr"`
	ServiceCIDR string `json:"serviceCidr"`
	Domain      string `json:"domain"`
}

type TelemetryBufferPayload struct {
	MaxMemoryMB      int    `json:"maxMemoryMB"`
	DiskSpoolEnabled bool   `json:"diskSpoolEnabled"`
	DiskSpoolDir     string `json:"diskSpoolDir"`
	DiskSpoolMaxMB   int    `json:"diskSpoolMaxMB"`
}

type NetFlowRemoteIface struct {
	IfIndex     uint32 `json:"ifIndex"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MacAddress  string `json:"macAddress,omitempty"`
	IPv4Address string `json:"ipv4Address,omitempty"`
}

type NetFlowRemoteLease struct {
	IP         string `json:"ip"`
	Hostname   string `json:"hostname"`
	MacAddress string `json:"macAddress,omitempty"`
}

type RemoteNodeMetadataPayload struct {
	NodeID      string                   `json:"nodeId"`
	Hostname    string                   `json:"hostname"`
	ExporterIP  string                   `json:"exporterIp,omitempty"`
	Interfaces  []NetFlowRemoteIface     `json:"interfaces,omitempty"`
	StaticHosts []NetFlowStaticHostEntry `json:"staticHosts,omitempty"`
	DhcpLeases  []NetFlowRemoteLease     `json:"dhcpLeases,omitempty"`
	TimestampMs int64                    `json:"timestampMs"`
}

type NetFlowNodeSummary struct {
	NodeID     string `json:"nodeId"`
	NodeName   string `json:"nodeName"`
	ExporterIP string `json:"exporterIp"`
	FlowsCount uint64 `json:"flowsCount"`
	LastSeenMs int64  `json:"lastSeenMs"`
}

type NetFlowRuntimeBundle struct {
	Enabled               bool                     `json:"enabled"`
	Mode                  string                   `json:"mode,omitempty"`
	NodeID                string                   `json:"nodeId,omitempty"`
	HubURL                string                   `json:"hubUrl,omitempty"`
	IngestToken           string                   `json:"ingestToken,omitempty"`
	UseHaMtls             bool                     `json:"useHaMtls,omitempty"`
	TLSCACert             string                   `json:"tlsCaCert,omitempty"`
	TLSInsecureSkipVerify bool                     `json:"tlsInsecureSkipVerify,omitempty"`
	Buffer                TelemetryBufferPayload   `json:"buffer,omitempty"`
	Config                NetFlowConfigPayload     `json:"config"`
	LocalHostname         string                   `json:"localHostname"`
	LocalInterfaces       []NetFlowInterfaceHint   `json:"localInterfaces"`
	StaticHostMap         []NetFlowStaticHostEntry `json:"staticHostMap"`
	K3sCidrs              NetFlowK3sCidrs          `json:"k3sCidrs"`
	ThreatCidrs           []NetFlowThreatEntry     `json:"threatCidrs"`
}

type FlowRecord struct {
	ID             string  `json:"id"`
	TimestampMs    int64   `json:"flowEndMs"`
	Timestamp      string  `json:"timestamp"`
	FlowStartMs    int64   `json:"flowStartMs,omitempty"`
	Version        string  `json:"version"` // netflow5 | netflow9 | ipfix | sflow5
	ExporterIP     string  `json:"exporterIp"`
	ExporterName   string  `json:"exporterName,omitempty"`
	SourceID       uint32  `json:"sourceId,omitempty"`
	SrcIP          string  `json:"srcIp"`
	DstIP          string  `json:"dstIp"`
	SrcPort        uint16  `json:"srcPort"`
	DstPort        uint16  `json:"dstPort"`
	Protocol       uint8   `json:"protocol"`
	ProtocolName   string  `json:"protocolName"`
	AppName        string  `json:"appName,omitempty"`
	SrcHost        string  `json:"srcHost,omitempty"`
	DstHost        string  `json:"dstHost,omitempty"`
	SrcAsn         uint32  `json:"srcAsn,omitempty"`
	SrcOrg         string  `json:"srcOrg,omitempty"`
	DstAsn         uint32  `json:"dstAsn,omitempty"`
	DstOrg         string  `json:"dstOrg,omitempty"`
	SrcCountry     string   `json:"srcCountry,omitempty"`
	DstCountry     string   `json:"dstCountry,omitempty"`
	SrcCity        string   `json:"srcCity,omitempty"`
	DstCity        string   `json:"dstCity,omitempty"`
	SrcLat         float64  `json:"srcLat,omitempty"`
	SrcLon         float64  `json:"srcLon,omitempty"`
	DstLat         float64  `json:"dstLat,omitempty"`
	DstLon         float64  `json:"dstLon,omitempty"`
	PeerAs         uint32   `json:"peerAs,omitempty"`
	AsPath         []uint32 `json:"asPath,omitempty"`
	BgpNextHop     string   `json:"bgpNextHop,omitempty"`
	Direction      string   `json:"direction,omitempty"` // internal | ingress | egress | transit
	InIfIndex      uint32   `json:"inIfIndex,omitempty"`
	OutIfIndex     uint32   `json:"outIfIndex,omitempty"`
	InIfName       string   `json:"inIfName,omitempty"`
	OutIfName      string   `json:"outIfName,omitempty"`
	VlanID         uint16   `json:"vlanId,omitempty"`
	Bytes          uint64   `json:"bytes"`
	Packets        uint64   `json:"packets"`
	Bps            float64  `json:"bps"`
	Pps            float64  `json:"pps,omitempty"`
	TCPFlags       uint8    `json:"tcpFlags,omitempty"`
	TCPFlagsStr    string   `json:"tcpFlagsStr,omitempty"`
	ToS            uint8    `json:"tos,omitempty"`
	DSCP           uint8    `json:"dscp,omitempty"`
	PostNatSrcIP   string   `json:"postNatSrcIp,omitempty"`
	PostNatDstIP   string   `json:"postNatDstIp,omitempty"`
	PostNatSrcPort uint16   `json:"postNatSrcPort,omitempty"`
	PostNatDstPort uint16   `json:"postNatDstPort,omitempty"`
	SrcMac         string   `json:"srcMac,omitempty"`
	DstMac         string   `json:"dstMac,omitempty"`
	K3sNamespace   string   `json:"k3sNamespace,omitempty"`
	K3sWorkload    string   `json:"k3sWorkload,omitempty"`
	K3sPodName     string   `json:"k3sPodName,omitempty"`
	K3sServiceName string   `json:"k3sServiceName,omitempty"`
	RttMs          float64  `json:"rttMs,omitempty"`
	Retransmits    uint32   `json:"retransmits,omitempty"`
	HostID         string   `json:"hostId,omitempty"`
	HostName       string   `json:"hostName,omitempty"`
	ThreatMatch    string   `json:"threatMatch,omitempty"`
	SamplingRate   uint32   `json:"samplingRate,omitempty"`
	FirewallEvent  uint8    `json:"firewallEvent,omitempty"`
}

type ExporterInterfaceCounter struct {
	ExporterIP  string `json:"exporterIp"`
	IfIndex     uint32 `json:"ifIndex"`
	IfName      string `json:"ifName,omitempty"`
	InOctets    uint64 `json:"inOctets"`
	OutOctets   uint64 `json:"outOctets"`
	InErrors    uint32 `json:"inErrors"`
	OutErrors   uint32 `json:"outErrors"`
	UpdatedAt   string `json:"updatedAt"`
}

type ExporterRuntimeStats struct {
	ExporterIP      string                     `json:"exporterIp"`
	Name            string                     `json:"name"`
	Vendor          string                     `json:"vendor"`
	Site            string                     `json:"site,omitempty"`
	LastSeen        string                     `json:"lastSeen"`
	LastSeenUnixMs  int64                      `json:"lastSeenUnixMs"`
	Status          string                     `json:"status"` // green | yellow | red
	Versions        []string                   `json:"versions"`
	PacketsReceived uint64                     `json:"packetsReceived"`
	FlowsReceived   uint64                     `json:"flowsReceived"`
	BytesAccounted  uint64                     `json:"bytesAccounted"`
	SamplingRate    uint32                     `json:"samplingRate"`
	TemplatesCount  int                        `json:"templatesCount"`
	FpsEstimate     float64                    `json:"fpsEstimate"`
	BpsEstimate     float64                    `json:"bpsEstimate"`
	Interfaces      []ExporterInterfaceCounter `json:"interfaces,omitempty"`
}

type TemplateFieldSpec struct {
	EnterpriseID uint32 `json:"enterpriseId,omitempty"`
	FieldType    uint16 `json:"fieldType"`
	FieldName    string `json:"fieldName"`
	Length       uint16 `json:"length"`
	IsScope      bool   `json:"isScope,omitempty"`
}

type TemplateCacheEntry struct {
	ExporterIP   string              `json:"exporterIp"`
	SourceID     uint32              `json:"sourceId"`
	Version      string              `json:"version"` // netflow9 | ipfix
	TemplateID   uint16              `json:"templateId"`
	IsOptions    bool                `json:"isOptions"`
	ScopeCount   int                 `json:"scopeCount,omitempty"`
	FieldCount   int                 `json:"fieldCount"`
	TotalBytes   int                 `json:"totalBytes"`
	UpdatedAt    string              `json:"updatedAt"`
	LastUsedAt   string              `json:"lastUsedAt"`
	PacketsUsing uint64              `json:"packetsUsing"`
	Fields       []TemplateFieldSpec `json:"fields"`
}

type FlowAlertEvent struct {
	ID           string  `json:"id"`
	Timestamp    string  `json:"timestamp"`
	RuleID       string  `json:"ruleId"`
	RuleName     string  `json:"ruleName"`
	Kind         string  `json:"kind"`
	Severity     string  `json:"severity"`
	CulpritIP    string  `json:"culpritIp"`
	ExporterIP   string  `json:"exporterIp,omitempty"`
	MetricValue  float64 `json:"metricValue"`
	Threshold    float64 `json:"threshold"`
	Summary      string  `json:"summary"`
	ActionsTaken []string `json:"actionsTaken"`
	Acknowledged bool    `json:"acknowledged"`
}

type FlowQueryRequest struct {
	RangeMinutes int      `json:"rangeMinutes"`
	StartMs      int64    `json:"startMs,omitempty"`
	EndMs        int64    `json:"endMs,omitempty"`
	FQL          string   `json:"fql,omitempty"`
	GroupBy      string   `json:"groupBy,omitempty"` // protocol | app | direction | src | dst | exporter | vlan
	Limit        int      `json:"limit,omitempty"`
	Offset       int      `json:"offset,omitempty"`
	SortBy       string   `json:"sortBy,omitempty"` // time | bytes | packets | bps
	Biflow       bool     `json:"biflow,omitempty"`
	Scope        string   `json:"scope,omitempty"`   // local | fleet
	PeerIDs      []string `json:"peerIds,omitempty"` // optional peer filter when Scope == "fleet"
}

type FlowSessionRecord struct {
	ID               string  `json:"id"`
	InitiatorIP      string  `json:"initiatorIp"`
	InitiatorHost    string  `json:"initiatorHost,omitempty"`
	ResponderIP      string  `json:"responderIp"`
	ResponderHost    string  `json:"responderHost,omitempty"`
	InitiatorPort    uint16  `json:"initiatorPort"`
	ResponderPort    uint16  `json:"responderPort"`
	Protocol         uint8   `json:"protocol"`
	ProtocolName     string  `json:"protocolName"`
	AppName          string  `json:"appName,omitempty"`
	Direction        string  `json:"direction,omitempty"`
	FirstSeenMs      int64   `json:"firstSeenMs"`
	LastSeenMs       int64   `json:"lastSeenMs"`
	DurationMs       int64   `json:"durationMs"`
	BytesFwd         uint64  `json:"bytesFwd"`
	BytesRev         uint64  `json:"bytesRev"`
	PacketsFwd       uint64  `json:"packetsFwd"`
	PacketsRev       uint64  `json:"packetsRev"`
	FlowsCount       int     `json:"flowsCount"`
	AsymmetryRatio   float64 `json:"asymmetryRatio"`
	UnansweredSyn    bool    `json:"unansweredSyn,omitempty"`
	AvgRttMs         float64 `json:"avgRttMs,omitempty"`
	TotalRetransmits uint32  `json:"totalRetransmits,omitempty"`
	ThreatMatch      string  `json:"threatMatch,omitempty"`
}

type FlowHeatmapMatrix struct {
	RowLabels []string   `json:"rowLabels"`
	ColLabels []string   `json:"colLabels"`
	Values    [][]uint64 `json:"values"`
	MaxValue  uint64     `json:"maxValue"`
}

type FlowGeoArc struct {
	SrcCountry string  `json:"srcCountry"`
	DstCountry string  `json:"dstCountry"`
	SrcCity    string  `json:"srcCity,omitempty"`
	DstCity    string  `json:"dstCity,omitempty"`
	SrcLat     float64 `json:"srcLat"`
	SrcLon     float64 `json:"srcLon"`
	DstLat     float64 `json:"dstLat"`
	DstLon     float64 `json:"dstLon"`
	Bytes      uint64  `json:"bytes"`
	Flows      int     `json:"flows"`
	Threat     bool    `json:"threat,omitempty"`
}

type FleetPeerError struct {
	PeerID   string `json:"peerId"`
	PeerName string `json:"peerName"`
	Error    string `json:"error"`
}

type FlowTimeseriesPoint struct {
	TimestampMs int64              `json:"timestampMs"`
	TimeLabel   string             `json:"timeLabel"`
	TotalBytes  uint64             `json:"totalBytes"`
	TotalPkts   uint64             `json:"totalPackets"`
	FlowsCount  int                `json:"flowsCount"`
	Bps         float64            `json:"bps"`
	Pps         float64            `json:"pps"`
	Series      map[string]float64 `json:"series"`
}

type FlowTopEntry struct {
	Key     string  `json:"key"`
	Label   string  `json:"label,omitempty"`
	Meta    string  `json:"meta,omitempty"`
	Bytes   uint64  `json:"bytes"`
	Packets uint64  `json:"packets"`
	Flows   int     `json:"flows"`
	Bps     float64 `json:"bps"`
}

type FlowConversationEntry struct {
	SrcIP        string  `json:"srcIp"`
	SrcHost      string  `json:"srcHost,omitempty"`
	DstIP        string  `json:"dstIp"`
	DstHost      string  `json:"dstHost,omitempty"`
	DstPort      uint16  `json:"dstPort"`
	ProtocolName string  `json:"protocolName"`
	AppName      string  `json:"appName,omitempty"`
	Direction    string  `json:"direction,omitempty"`
	Bytes        uint64  `json:"bytes"`
	Packets      uint64  `json:"packets"`
	Flows        int     `json:"flows"`
	Bps          float64 `json:"bps"`
	ThreatMatch  string  `json:"threatMatch,omitempty"`
}

type FlowSankeyLink struct {
	Source string  `json:"source"`
	Target string  `json:"target"`
	Bytes  uint64  `json:"bytes"`
	Stage  string  `json:"stage"` // src-to-app | app-to-dst
}

type FlowQueryResponse struct {
	Timestamp         string                  `json:"timestamp"`
	Engine            string                  `json:"engine,omitempty"` // local-ring | local-chunks | local-rollups | clickhouse | federated
	FQLError          string                  `json:"fqlError,omitempty"`
	TotalMatchedFlows int                     `json:"totalMatchedFlows"`
	TotalBytes        uint64                  `json:"totalBytes"`
	TotalPackets      uint64                  `json:"totalPackets"`
	AvgBps            float64                 `json:"avgBps"`
	UniqueSources     int                     `json:"uniqueSources"`
	UniqueDests       int                     `json:"uniqueDestinations"`
	SeriesKeys        []string                `json:"seriesKeys"`
	Timeseries        []FlowTimeseriesPoint   `json:"timeseries"`
	TopSources        []FlowTopEntry          `json:"topSources"`
	TopDestinations   []FlowTopEntry          `json:"topDestinations"`
	TopApps           []FlowTopEntry          `json:"topApps"`
	TopProtocols      []FlowTopEntry          `json:"topProtocols"`
	TopCountries      []FlowTopEntry          `json:"topCountries"`
	TopASNs           []FlowTopEntry          `json:"topAsns"`
	TopExporters      []FlowTopEntry          `json:"topExporters"`
	TopInterfaces     []FlowTopEntry          `json:"topInterfaces"`
	TopVLANs          []FlowTopEntry          `json:"topVlans"`
	TopConversations  []FlowConversationEntry `json:"topConversations"`
	SankeyLinks       []FlowSankeyLink        `json:"sankeyLinks"`
	Flows             []FlowRecord            `json:"flows"`
	Sessions          []FlowSessionRecord     `json:"sessions,omitempty"`
	HostHeatmap       *FlowHeatmapMatrix      `json:"hostHeatmap,omitempty"`
	PortTimeHeatmap   *FlowHeatmapMatrix      `json:"portTimeHeatmap,omitempty"`
	GeoArcs           []FlowGeoArc            `json:"geoArcs,omitempty"`
	PeerErrors        []FleetPeerError        `json:"peerErrors,omitempty"`
}

type NetFlowListenerStatus struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Protocol        string `json:"protocol"`
	Transport       string `json:"transport"`
	Address         string `json:"address"`
	Listening       bool   `json:"listening"`
	PacketsReceived uint64 `json:"packetsReceived"`
	DecodeErrors    uint64 `json:"decodeErrors"`
	DroppedUnknownT uint64 `json:"droppedUnknownTemplates"`
	LastError       string `json:"lastError,omitempty"`
}

type NetFlowStatusSnapshot struct {
	Enabled             bool                    `json:"enabled"`
	Running             bool                    `json:"running"`
	Timestamp           string                  `json:"timestamp"`
	Listeners           []NetFlowListenerStatus `json:"listeners"`
	PacketsReceived     uint64                  `json:"packetsReceived"`
	FlowsIngested       uint64                  `json:"flowsIngested"`
	BytesIngested       uint64                  `json:"bytesIngested"`
	ReplicatedPackets   uint64                  `json:"replicatedPackets"`
	SelfExportedFlows   uint64                  `json:"selfExportedFlows"`
	DecodeErrors        uint64                  `json:"decodeErrors"`
	HotRingCount        int                     `json:"hotRingCount"`
	HotRingCapacity     int                     `json:"hotRingCapacity"`
	DiskChunksCount     int                     `json:"diskChunksCount"`
	DiskUsageMB         float64                 `json:"diskUsageMb"`
	StorageMode         string                  `json:"storageMode"`
	ClickHouseConnected bool                    `json:"clickHouseConnected"`
	ExportersCount      int                     `json:"exportersCount"`
	TemplatesCount      int                     `json:"templatesCount"`
	ActiveAlertsCount   int                     `json:"activeAlertsCount"`
	GeoIPCityLoaded     bool                    `json:"geoipCityLoaded"`
	GeoIPAsnLoaded      bool                    `json:"geoipAsnLoaded"`
	GeoIPUpdatedAt      string                  `json:"geoipUpdatedAt,omitempty"`
	BaselineEntities    int                     `json:"baselineEntities"`
	BgpPrefixes         int                     `json:"bgpPrefixes"`
	K3sWorkloads        int                     `json:"k3sWorkloads"`
	LastError           string                  `json:"lastError,omitempty"`
}

type NetFlowReportRequest struct {
	RangeDays int    `json:"rangeDays"`
	GroupBy   string `json:"groupBy"` // interface | exporter | vlan | subnet
	Format    string `json:"format"`  // json | csv | markdown
}

type NetFlowPercentileRow struct {
	GroupKey    string  `json:"groupKey"`
	P95Bps      float64 `json:"p95Bps"`
	P99Bps      float64 `json:"p99Bps"`
	PeakBps     float64 `json:"peakBps"`
	AvgBps      float64 `json:"avgBps"`
	TotalBytes  uint64  `json:"totalBytes"`
	TotalFlows  int     `json:"totalFlows"`
	SampleCount int     `json:"sampleCount"`
}

type NetFlowReportResponse struct {
	GeneratedAt    string                 `json:"generatedAt"`
	RangeDays      int                    `json:"rangeDays"`
	StartMs        int64                  `json:"startMs"`
	EndMs          int64                  `json:"endMs"`
	GroupBy        string                 `json:"groupBy"`
	BucketSeconds  int                    `json:"bucketSeconds"`
	Rows           []NetFlowPercentileRow `json:"rows"`
	SavedSnapshots []string               `json:"savedSnapshots,omitempty"`
	Rendered       string                 `json:"rendered,omitempty"`
}

type BaselineSummaryEntry struct {
	Entity      string  `json:"entity"`
	DayOfWeek   int     `json:"dayOfWeek"`
	HourOfDay   int     `json:"hourOfDay"`
	Samples     int     `json:"samples"`
	EwmaBps     float64 `json:"ewmaBps"`
	StddevBps   float64 `json:"stddevBps"`
	EwmaPps     float64 `json:"ewmaPps"`
	StddevPps   float64 `json:"stddevPps"`
	LastSeenSec int64   `json:"lastSeenSec"`
}

type NetFlowTopologyInterfaceRate struct {
	ExporterIP string  `json:"exporterIp"`
	Device     string  `json:"device"`
	RxBps      float64 `json:"rxBps"`
	TxBps      float64 `json:"txBps"`
	Flows      int     `json:"flows"`
}

type NetFlowTopologyOverlay struct {
	Available  bool                           `json:"available"`
	Timestamp  string                         `json:"timestamp"`
	WindowSec  int                            `json:"windowSec"`
	TotalBps   float64                        `json:"totalBps"`
	TotalFlows int                            `json:"totalFlows"`
	Interfaces []NetFlowTopologyInterfaceRate `json:"interfaces"`
}
