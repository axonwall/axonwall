package engine

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	libreNmsMaskedPlaceholder = "********"
	libreNmsMaxWebhookAlerts  = 200
)

type LibreNMSSnmpDefaults struct {
	Version      string `json:"version"`
	Community    string `json:"community,omitempty"`
	Port         int    `json:"port"`
	V3AuthLevel  string `json:"v3AuthLevel,omitempty"`
	V3AuthUser   string `json:"v3AuthUser,omitempty"`
	V3AuthAlgo   string `json:"v3AuthAlgo,omitempty"`
	V3CryptoAlgo string `json:"v3CryptoAlgo,omitempty"`
}

type LibreNMSSyncConfig struct {
	Enabled                   bool `json:"enabled"`
	AutoEnrollAxonwallHosts   bool `json:"autoEnrollAxonwallHosts"`
	AutoEnrollFleetSatellites bool `json:"autoEnrollFleetSatellites"`
	AutoEnrollTopologyPeers   bool `json:"autoEnrollTopologyPeers"`
	SyncToNetBox              bool `json:"syncToNetBox"`
	PollIntervalSec           int  `json:"pollIntervalSec"`
}

type LibreNMSConfigMetadata struct {
	Enabled         bool                 `json:"enabled"`
	Mode            string               `json:"mode"`
	Namespace       string               `json:"namespace"`
	Domain          string               `json:"domain"`
	ServicePort     int                  `json:"servicePort"`
	AdminUsername   string               `json:"adminUsername"`
	AdminEmail      string               `json:"adminEmail"`
	ExternalURL     string               `json:"externalUrl,omitempty"`
	SyslogEnabled   bool                 `json:"syslogEnabled"`
	SnmpTrapEnabled bool                 `json:"snmpTrapEnabled"`
	SnmpDefaults    LibreNMSSnmpDefaults `json:"snmpDefaults"`
	Sync            LibreNMSSyncConfig   `json:"sync"`
}

type LibreNMSEnrollmentTarget struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	DisplayName string `json:"displayName"`
	Source      string `json:"source"`
	SnmpVersion string `json:"snmpVersion"`
	Port        int    `json:"port"`
	SysRole     string `json:"sysRole"`
}

type LibreNMSEnrollmentPlan struct {
	SnmpEnabledOnLocal bool                       `json:"snmpEnabledOnLocal"`
	Targets            []LibreNMSEnrollmentTarget `json:"targets"`
	DiscoverySubnets   []struct {
		CIDR  string `json:"cidr"`
		Label string `json:"label"`
	} `json:"discoverySubnets"`
	Summary struct {
		TargetsCount int `json:"targetsCount"`
		SubnetsCount int `json:"subnetsCount"`
	} `json:"summary"`
}

type LibreNMSRuntimeBundle struct {
	Enabled            bool                   `json:"enabled"`
	K3sDependencyMet   bool                   `json:"k3sDependencyMet"`
	Mode               string                 `json:"mode"`
	Config             LibreNMSConfigMetadata `json:"config"`
	Namespace          string                 `json:"namespace"`
	Domain             string                 `json:"domain"`
	EndpointURL        string                 `json:"endpointUrl"`
	InternalServiceURL string                 `json:"internalServiceUrl"`
	K3sManifestsYaml   string                 `json:"k3sManifestsYaml"`
	UnboundOverrides   string                 `json:"unboundOverrides"`
	EnrollmentPlan     LibreNMSEnrollmentPlan `json:"enrollmentPlan"`
	APIToken           string                 `json:"apiToken,omitempty"`
	WebhookSecret      string                 `json:"webhookSecret,omitempty"`
	AdminPassword      string                 `json:"adminPassword,omitempty"`
	SnmpV3AuthPass     string                 `json:"snmpV3AuthPass,omitempty"`
	SnmpV3CryptoPass   string                 `json:"snmpV3CryptoPass,omitempty"`
	SnmpCommunity      string                 `json:"snmpCommunity,omitempty"`
}

type libreNmsHostSecrets struct {
	DBPassword       string `json:"dbPassword"`
	DBRootPassword   string `json:"dbRootPassword"`
	AppKey           string `json:"appKey"`
	AdminPassword    string `json:"adminPassword"`
	APIToken         string `json:"apiToken"`
	WebhookSecret    string `json:"webhookSecret"`
	SnmpCommunity    string `json:"snmpCommunity,omitempty"`
	SnmpV3AuthPass   string `json:"snmpV3AuthPass,omitempty"`
	SnmpV3CryptoPass string `json:"snmpV3CryptoPass,omitempty"`
}

type LibreNMSDevice struct {
	DeviceID int    `json:"deviceId"`
	Hostname string `json:"hostname"`
	SysName  string `json:"sysName,omitempty"`
	IP       string `json:"ip,omitempty"`
	OS       string `json:"os,omitempty"`
	Hardware string `json:"hardware,omitempty"`
	Version  string `json:"version,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Status   bool   `json:"status"`
	Disabled bool   `json:"disabled"`
	Location string `json:"location,omitempty"`
	Purpose  string `json:"purpose,omitempty"`
	Uptime   int64  `json:"uptime,omitempty"`
}

type LibreNMSPort struct {
	PortID        int     `json:"portId"`
	DeviceID      int     `json:"deviceId"`
	IfIndex       int     `json:"ifIndex,omitempty"`
	DeviceHost    string  `json:"deviceHost,omitempty"`
	IfName        string  `json:"ifName"`
	IfDescr       string  `json:"ifDescr,omitempty"`
	IfAlias       string  `json:"ifAlias,omitempty"`
	IfOperStatus  string  `json:"ifOperStatus"`
	IfAdminStatus string  `json:"ifAdminStatus"`
	IfSpeedBps    int64   `json:"ifSpeedBps,omitempty"`
	InRateBps     float64 `json:"inRateBps,omitempty"`
	OutRateBps    float64 `json:"outRateBps,omitempty"`
	InErrors      int64   `json:"inErrors,omitempty"`
	OutErrors     int64   `json:"outErrors,omitempty"`
	IfVlan        string  `json:"ifVlan,omitempty"`
	IfMtu         int     `json:"ifMtu,omitempty"`
	IfPhysAddress string  `json:"ifPhysAddress,omitempty"`
	IfType        string  `json:"ifType,omitempty"`
}

type LibreNMSLink struct {
	ID             int    `json:"id"`
	LocalDeviceID  int    `json:"localDeviceId"`
	LocalDevice    string `json:"localDevice,omitempty"`
	LocalPortID    int    `json:"localPortId"`
	LocalPort      string `json:"localPort"`
	RemoteDeviceID int    `json:"remoteDeviceId,omitempty"`
	RemoteDevice   string `json:"remoteDevice"`
	RemotePortID   int    `json:"remotePortId,omitempty"`
	RemotePort     string `json:"remotePort"`
	Protocol       string `json:"protocol"`
	Active         bool   `json:"active"`
}

type LibreNMSFDBEntry struct {
	DeviceID  int    `json:"deviceId"`
	PortID    int    `json:"portId"`
	VlanID    int    `json:"vlanId,omitempty"`
	MacAddr   string `json:"macAddress"`
}

type LibreNMSARPEntry struct {
	DeviceID  int    `json:"deviceId"`
	PortID    int    `json:"portId,omitempty"`
	MacAddr   string `json:"macAddress"`
	IPAddress string `json:"ipAddress"`
}

type LibreNMSHealthSensor struct {
	DeviceID  int     `json:"deviceId"`
	Class     string  `json:"class"`
	Descr     string  `json:"descr"`
	Current   float64 `json:"current"`
	HighLimit float64 `json:"highLimit,omitempty"`
	LowLimit  float64 `json:"lowLimit,omitempty"`
	Alerted   bool    `json:"alerted"`
}

type LibreNMSWebhookAlert struct {
	ID             string `json:"id"`
	DeviceID       int    `json:"deviceId,omitempty"`
	DeviceHostname string `json:"deviceHostname"`
	DeviceIP       string `json:"deviceIp,omitempty"`
	Rule           string `json:"rule"`
	Severity       string `json:"severity"`
	State          int    `json:"state"`
	Timestamp      string `json:"timestamp"`
	PortName       string `json:"portName,omitempty"`
	Message        string `json:"message"`
	Source         string `json:"source"`
}

type LibreNMSTopologySnapshot struct {
	Available     bool                   `json:"available"`
	Endpoint      string                 `json:"endpoint,omitempty"`
	Timestamp     string                 `json:"timestamp"`
	Devices       []LibreNMSDevice       `json:"devices"`
	Ports         []LibreNMSPort         `json:"ports"`
	Links         []LibreNMSLink         `json:"links"`
	FDB           []LibreNMSFDBEntry     `json:"fdb"`
	ARP           []LibreNMSARPEntry     `json:"arp"`
	HealthSensors []LibreNMSHealthSensor `json:"healthSensors"`
	Alerts        []LibreNMSWebhookAlert `json:"alerts"`
	WebhookAlerts []LibreNMSWebhookAlert `json:"webhookAlerts"`
	Error         string                 `json:"error,omitempty"`
}

type LibreNMSSyncRequest struct {
	DryRun           bool   `json:"dryRun"`
	EndpointOverride string `json:"endpointOverride,omitempty"`
}

type LibreNMSSyncResult struct {
	Success   bool     `json:"success"`
	DryRun    bool     `json:"dryRun"`
	Timestamp string   `json:"timestamp"`
	Endpoint  string   `json:"endpoint"`
	Enrolled  int      `json:"enrolled"`
	Existing  int      `json:"existing"`
	Failed    int      `json:"failed"`
	Subnets   int      `json:"subnets"`
	Warnings  []string `json:"warnings,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type LibreNMSStatus struct {
	Enabled            bool                    `json:"enabled"`
	Mode               string                  `json:"mode"`
	K3sDependencyMet   bool                    `json:"k3sDependencyMet"`
	K3sReady           bool                    `json:"k3sReady"`
	ManifestPresent    bool                    `json:"manifestPresent"`
	LDAPBound          bool                    `json:"ldapBound"`
	APIReachable       bool                    `json:"apiReachable"`
	LibreNMSVersion    string                  `json:"librenmsVersion,omitempty"`
	Namespace          string                  `json:"namespace"`
	Domain             string                  `json:"domain"`
	EndpointURL        string                  `json:"endpointUrl"`
	InternalServiceURL string                  `json:"internalServiceUrl"`
	ClusterIP          string                  `json:"clusterIp,omitempty"`
	DeviceCount        int                     `json:"deviceCount"`
	PortCount          int                     `json:"portCount"`
	LinkCount          int                     `json:"linkCount"`
	ActiveAlertCount   int                     `json:"activeAlertCount"`
	WebhookAlertCount  int                     `json:"webhookAlertCount"`
	Pods               []K3sAppPodStatus       `json:"pods"`
	PodReadyCount      int                     `json:"podReadyCount"`
	PodTotalCount      int                     `json:"podTotalCount"`
	LastSync           *LibreNMSSyncResult     `json:"lastSync,omitempty"`
	EnrollmentPlan     *LibreNMSEnrollmentPlan `json:"enrollmentPlan,omitempty"`
	StatusError        string                  `json:"statusError,omitempty"`
}

type LibreNMSCredentialsSummary struct {
	Configured         bool   `json:"configured"`
	AdminUsername      string `json:"adminUsername"`
	AdminEmail         string `json:"adminEmail"`
	EndpointURL        string `json:"endpointUrl"`
	InternalServiceURL string `json:"internalServiceUrl"`
	WebhookPath        string `json:"webhookPath"`
	TokenPreview       string `json:"tokenPreview,omitempty"`
	APIToken           string `json:"apiToken,omitempty"`
	AdminPassword      string `json:"adminPassword,omitempty"`
	WebhookSecret      string `json:"webhookSecret,omitempty"`
}

type LibreNMSNetBoxSyncRequest struct {
	Action           string `json:"action"` // "preview" | "push" | "pull"
	DryRun           bool   `json:"dryRun"`
	OverwriteLabels  bool   `json:"overwriteLabels,omitempty"`
	EndpointOverride string `json:"endpointOverride,omitempty"`
	NetBoxOverride   string `json:"netboxOverride,omitempty"`
}

type LibreNMSNetBoxSyncResult struct {
	Success        bool                    `json:"success"`
	Action         string                  `json:"action"`
	DryRun         bool                    `json:"dryRun"`
	Timestamp      string                  `json:"timestamp"`
	LibreNMSEndpoint string                `json:"librenmsEndpoint,omitempty"`
	NetBoxEndpoint string                  `json:"netboxEndpoint,omitempty"`
	DevicesQueued  int                     `json:"devicesQueued"`
	CablesQueued   int                     `json:"cablesQueued"`
	NetBoxResult   *NetBoxCablesSyncResult `json:"netboxResult,omitempty"`
	PullResult     *LibreNMSSyncResult     `json:"pullResult,omitempty"`
	Warnings       []string                `json:"warnings,omitempty"`
	Error          string                  `json:"error,omitempty"`
}

type LibreNMSManager struct {
	mu              sync.Mutex
	configDir       string
	manifestDir     string
	ldapBindingPath string
	k3sManager      *K3sManager
	netboxManager   *NetBoxManager
	httpClient      *http.Client
	kubectlRunner   func(ctx context.Context, args ...string) ([]byte, error)
	webhookAlerts   []LibreNMSWebhookAlert
}

func NewLibreNMSManager(configDir string, k3sManager *K3sManager, netboxManager *NetBoxManager) *LibreNMSManager {
	return &LibreNMSManager{
		configDir:       configDir,
		manifestDir:     k3sServerManifestDir,
		ldapBindingPath: filepath.Join(LDAPPluginClientsDir, "librenms.json"),
		k3sManager:      k3sManager,
		netboxManager:   netboxManager,
		httpClient:      newInternalK3sHTTPClient(8 * time.Second),
		webhookAlerts:   []LibreNMSWebhookAlert{},
	}
}

func (m *LibreNMSManager) manifestPath() string {
	dir := m.manifestDir
	if dir == "" {
		dir = k3sServerManifestDir
	}
	return filepath.Join(dir, "axonwall-librenms.yaml")
}

func (m *LibreNMSManager) loadSavedBundle() (*LibreNMSRuntimeBundle, error) {
	data, err := os.ReadFile(filepath.Join(m.configDir, "config.json"))
	if err != nil {
		return nil, err
	}
	var bundle LibreNMSRuntimeBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func (m *LibreNMSManager) ensureSecretsLocked(bundle *LibreNMSRuntimeBundle) (*libreNmsHostSecrets, error) {
	if err := os.MkdirAll(m.configDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create librenms config dir %q: %w", m.configDir, err)
	}
	secPath := filepath.Join(m.configDir, "secrets.json")
	sec := &libreNmsHostSecrets{}
	loaded := false
	if raw, err := os.ReadFile(secPath); err == nil {
		if json.Unmarshal(raw, sec) == nil {
			loaded = true
		}
	}

	dirty := !loaded
	genHexIfEmpty := func(field *string, numBytes int) error {
		if *field != "" {
			return nil
		}
		v, err := randomHexToken(numBytes)
		if err != nil {
			return err
		}
		*field = v
		dirty = true
		return nil
	}

	if err := genHexIfEmpty(&sec.DBPassword, 16); err != nil {
		return nil, err
	}
	if err := genHexIfEmpty(&sec.DBRootPassword, 16); err != nil {
		return nil, err
	}
	if err := genHexIfEmpty(&sec.AdminPassword, 12); err != nil {
		return nil, err
	}
	if err := genHexIfEmpty(&sec.APIToken, 20); err != nil {
		return nil, err
	}
	if err := genHexIfEmpty(&sec.WebhookSecret, 20); err != nil {
		return nil, err
	}
	if sec.AppKey == "" {
		v, err := randomHexToken(16)
		if err != nil {
			return nil, err
		}
		// 32 ASCII bytes for Laravel AES-256-CBC APP_KEY
		sec.AppKey = v
		dirty = true
	}

	if bundle != nil {
		applyOverride := func(dst *string, val string) {
			clean := strings.TrimSpace(val)
			if clean != "" && clean != libreNmsMaskedPlaceholder && clean != *dst {
				*dst = clean
				dirty = true
			}
		}
		applyOverride(&sec.APIToken, bundle.APIToken)
		applyOverride(&sec.WebhookSecret, bundle.WebhookSecret)
		applyOverride(&sec.AdminPassword, bundle.AdminPassword)
		applyOverride(&sec.SnmpCommunity, bundle.SnmpCommunity)
		applyOverride(&sec.SnmpV3AuthPass, bundle.SnmpV3AuthPass)
		applyOverride(&sec.SnmpV3CryptoPass, bundle.SnmpV3CryptoPass)
	}

	if dirty {
		encoded, err := json.MarshalIndent(sec, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := writeFilesAtomic([]atomicFileWrite{
			{path: secPath, content: string(encoded) + "\n", perm: 0600},
		}); err != nil {
			return nil, fmt.Errorf("failed to persist librenms secrets: %w", err)
		}
	}

	return sec, nil
}

func (m *LibreNMSManager) ApplyConfig(rawJSON []byte) error {
	var bundle LibreNMSRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return fmt.Errorf("invalid librenms runtime bundle json: %w", err)
	}
	if bundle.Mode == "" {
		bundle.Mode = "k3s"
	}
	if strings.TrimSpace(bundle.EndpointURL) != "" {
		validURL, err := validatePluginHTTPURL(bundle.EndpointURL, "librenms")
		if err != nil {
			return fmt.Errorf("librenms bundle rejected: %w", err)
		}
		bundle.EndpointURL = validURL
	}
	if strings.TrimSpace(bundle.InternalServiceURL) != "" {
		validInternal, err := validatePluginHTTPURL(bundle.InternalServiceURL, "librenms internal")
		if err != nil {
			return fmt.Errorf("librenms bundle rejected: %w", err)
		}
		bundle.InternalServiceURL = validInternal
	}

	sanitizedBundle := bundle
	sanitizedBundle.APIToken = ""
	sanitizedBundle.WebhookSecret = ""
	sanitizedBundle.AdminPassword = ""
	sanitizedBundle.SnmpV3AuthPass = ""
	sanitizedBundle.SnmpV3CryptoPass = ""
	sanitizedBundle.SnmpCommunity = ""
	sanitizedBundle.K3sManifestsYaml = ""
	sanitizedBytes, err := json.MarshalIndent(sanitizedBundle, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode sanitized librenms config: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.configDir, 0750); err != nil {
		return fmt.Errorf("failed to create librenms config dir %q: %w", m.configDir, err)
	}

	secrets, err := m.ensureSecretsLocked(&bundle)
	if err != nil {
		return err
	}

	mPath := m.manifestPath()
	shouldDeployK3s := bundle.Enabled && bundle.Mode == "k3s" && bundle.K3sDependencyMet && strings.TrimSpace(bundle.K3sManifestsYaml) != ""
	if !shouldDeployK3s {
		if err := removeFileIfExists(mPath); err != nil {
			return fmt.Errorf("failed to remove stale librenms manifest %q: %w", mPath, err)
		}
		return writeFilesAtomic([]atomicFileWrite{
			{path: filepath.Join(m.configDir, "config.json"), content: string(sanitizedBytes) + "\n", perm: 0600},
		})
	}

	ldapBindPass := readPluginLDAPBindPasswordFromFile(m.ldapBindingPath, "librenms")
	replacer := strings.NewReplacer(
		`"__AXONWALL_LIBRENMS_DB_PASSWORD__"`, strconv.Quote(secrets.DBPassword),
		`"__AXONWALL_LIBRENMS_DB_ROOT_PASSWORD__"`, strconv.Quote(secrets.DBRootPassword),
		`"__AXONWALL_LIBRENMS_APP_KEY__"`, strconv.Quote(secrets.AppKey),
		`"__AXONWALL_LIBRENMS_ADMIN_PASSWORD__"`, strconv.Quote(secrets.AdminPassword),
		`"__AXONWALL_LIBRENMS_API_TOKEN__"`, strconv.Quote(secrets.APIToken),
		`"__AXONWALL_LIBRENMS_LDAP_BIND_PASSWORD__"`, strconv.Quote(ldapBindPass),
	)
	renderedManifest := replacer.Replace(bundle.K3sManifestsYaml)

	// Security invariant: validate rendered YAML BEFORE touching any files on disk
	if err := validateK3sManifest(renderedManifest); err != nil {
		return fmt.Errorf("librenms bundle rejected: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(mPath), 0755); err != nil {
		return fmt.Errorf("failed to create librenms manifest dir %q: %w", filepath.Dir(mPath), err)
	}

	if err := writeFilesAtomic([]atomicFileWrite{
		{path: filepath.Join(m.configDir, "config.json"), content: string(sanitizedBytes) + "\n", perm: 0600},
		{path: mPath, content: renderedManifest, perm: 0600},
	}); err != nil {
		return err
	}

	slog.Info("Reconciled LibreNMS K3s deployment manifests", "namespace", bundle.Namespace, "domain", bundle.Domain)
	return nil
}

func (m *LibreNMSManager) resolveReachableBaseURL(bundle *LibreNMSRuntimeBundle, clusterIP string) string {
	if bundle == nil {
		return "http://librenms.librenms.svc.cluster.local:8000"
	}
	if bundle.Mode == "external" && strings.TrimSpace(bundle.EndpointURL) != "" {
		return strings.TrimRight(bundle.EndpointURL, "/")
	}
	if clusterIP != "" {
		port := bundle.Config.ServicePort
		if port <= 0 {
			port = 8000
		}
		return fmt.Sprintf("http://%s:%d", clusterIP, port)
	}
	if strings.TrimSpace(bundle.EndpointURL) != "" {
		return strings.TrimRight(bundle.EndpointURL, "/")
	}
	if strings.TrimSpace(bundle.InternalServiceURL) != "" {
		return strings.TrimRight(bundle.InternalServiceURL, "/")
	}
	return "http://librenms.librenms.svc.cluster.local:8000"
}

type libreNmsAPIClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func (c *libreNmsAPIClient) doJSON(ctx context.Context, method, path string, payload any) (int, map[string]any, error) {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("X-Auth-Token", c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var decoded map[string]any
	if len(respBytes) > 0 {
		_ = json.Unmarshal(respBytes, &decoded)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errSnippet := sanitizeHTTPErrorBody(respBytes, 256)
		if errSnippet == "" {
			return resp.StatusCode, decoded, fmt.Errorf("%s %s returned HTTP %d", method, path, resp.StatusCode)
		}
		return resp.StatusCode, decoded, fmt.Errorf("%s %s returned HTTP %d: %s", method, path, resp.StatusCode, errSnippet)
	}
	return resp.StatusCode, decoded, nil
}

func asInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int:
		return int64(x)
	case int64:
		return x
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	default:
		return 0
	}
}

func asFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	default:
		return 0
	}
}

func asBoolFlex(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case int:
		return x != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "1" || s == "true" || s == "up" || s == "yes"
	default:
		return false
	}
}

func (m *LibreNMSManager) resolveClient(ctx context.Context, endpointOverride string) (*libreNmsAPIClient, *LibreNMSRuntimeBundle, *libreNmsHostSecrets, error) {
	m.mu.Lock()
	bundle, err := m.loadSavedBundle()
	sec, secErr := m.ensureSecretsLocked(nil)
	m.mu.Unlock()
	if err != nil || bundle == nil {
		return nil, nil, nil, fmt.Errorf("LibreNMS plugin has not been configured on this host yet (save & apply LibreNMS settings first)")
	}
	if secErr != nil {
		return nil, bundle, nil, secErr
	}

	clusterIP := ""
	if bundle.Mode != "external" && bundle.Enabled {
		_, clusterIP = inspectK3sAppPodsAndService(ctx, m.kubectlRunner, bundle.Namespace, "librenms")
	}
	autoEndpoint := m.resolveReachableBaseURL(bundle, clusterIP)
	endpoint := strings.TrimSpace(endpointOverride)
	if endpoint == "" {
		endpoint = autoEndpoint
	}
	validEndpoint, urlErr := validatePluginHTTPURL(endpoint, "librenms")
	if urlErr != nil {
		return nil, bundle, sec, urlErr
	}
	configuredBases := []string{bundle.EndpointURL, bundle.InternalServiceURL, autoEndpoint}
	tok := tokenIfSameOrigin(endpointOverride, configuredBases, sec.APIToken)
	return &libreNmsAPIClient{
		baseURL:    validEndpoint,
		token:      tok,
		httpClient: m.httpClient,
	}, bundle, sec, nil
}

func (m *LibreNMSManager) probeAPI(ctx context.Context, client *libreNmsAPIClient) (bool, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	_, data, err := client.doJSON(reqCtx, http.MethodGet, "/api/v0/system", nil)
	if err != nil {
		return false, "", err
	}
	if sysList, ok := data["system"].([]any); ok && len(sysList) > 0 {
		if sysMap, ok := sysList[0].(map[string]any); ok {
			ver := asStr(sysMap["local_ver"])
			return true, ver, nil
		}
	}
	return true, "", nil
}

func (m *LibreNMSManager) GetStatus(ctx context.Context) LibreNMSStatus {
	st := LibreNMSStatus{
		Mode:               "k3s",
		Namespace:          "librenms",
		Domain:             "librenms.axonwall.local",
		EndpointURL:        "https://librenms.axonwall.local",
		InternalServiceURL: "http://librenms.librenms.svc.cluster.local:8000",
		Pods:               []K3sAppPodStatus{},
	}

	if _, err := os.Stat(m.manifestPath()); err == nil {
		st.ManifestPresent = true
	}
	ldapPath := m.ldapBindingPath
	if ldapPath == "" {
		ldapPath = filepath.Join(LDAPPluginClientsDir, "librenms.json")
	}
	if _, err := os.Stat(ldapPath); err == nil {
		st.LDAPBound = true
	}

	if m.k3sManager != nil {
		k3sSt := m.k3sManager.GetStatus()
		st.K3sReady = k3sSt.Running && k3sSt.ServiceActive
		st.K3sDependencyMet = k3sSt.Enabled
	}

	m.mu.Lock()
	bundle, loadErr := m.loadSavedBundle()
	sec, _ := m.ensureSecretsLocked(nil)
	webhookCount := len(m.webhookAlerts)
	if lastRaw, err := os.ReadFile(filepath.Join(m.configDir, "last-sync.json")); err == nil {
		var lr LibreNMSSyncResult
		if json.Unmarshal(lastRaw, &lr) == nil {
			st.LastSync = &lr
		}
	}
	m.mu.Unlock()
	st.WebhookAlertCount = webhookCount

	if loadErr != nil || bundle == nil {
		return st
	}

	st.Enabled = bundle.Enabled
	if bundle.Mode != "" {
		st.Mode = bundle.Mode
	}
	if bundle.K3sDependencyMet || st.Mode == "external" {
		st.K3sDependencyMet = true
	}
	if bundle.Namespace != "" {
		st.Namespace = bundle.Namespace
	}
	if bundle.Domain != "" {
		st.Domain = bundle.Domain
	}
	if bundle.EndpointURL != "" {
		st.EndpointURL = bundle.EndpointURL
	}
	if bundle.InternalServiceURL != "" {
		st.InternalServiceURL = bundle.InternalServiceURL
	}
	planCopy := bundle.EnrollmentPlan
	st.EnrollmentPlan = &planCopy

	if !st.Enabled {
		return st
	}

	var clusterIP string
	if st.Mode == "k3s" && st.K3sReady {
		pods, cip := inspectK3sAppPodsAndService(ctx, m.kubectlRunner, st.Namespace, "librenms")
		st.Pods = pods
		st.ClusterIP = cip
		clusterIP = cip
		st.PodTotalCount = len(pods)
		for _, p := range pods {
			if p.Ready {
				st.PodReadyCount++
			}
		}
	}

	if st.Mode == "external" || st.K3sReady {
		token := ""
		if sec != nil {
			token = sec.APIToken
		}
		probeURL := m.resolveReachableBaseURL(bundle, clusterIP)
		if validURL, err := validatePluginHTTPURL(probeURL, "librenms"); err == nil {
			client := &libreNmsAPIClient{
				baseURL:    validURL,
				token:      token,
				httpClient: m.httpClient,
			}
			if ok, ver, err := m.probeAPI(ctx, client); ok {
				st.APIReachable = true
				st.LibreNMSVersion = ver
				snap := m.GetTopologySnapshot(ctx, validURL)
				if snap.Available {
					st.DeviceCount = len(snap.Devices)
					st.PortCount = len(snap.Ports)
					st.LinkCount = len(snap.Links)
					st.ActiveAlertCount = len(snap.Alerts)
				}
			} else if err != nil {
				st.StatusError = err.Error()
			}
		}
	}

	return st
}

func (m *LibreNMSManager) GetBootstrapCredentials(reveal bool) (*LibreNMSCredentialsSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bundle, err := m.loadSavedBundle()
	if err != nil {
		return &LibreNMSCredentialsSummary{
			Configured:         false,
			AdminUsername:      "admin",
			AdminEmail:         "admin@axonwall.local",
			EndpointURL:        "https://librenms.axonwall.local",
			InternalServiceURL: "http://librenms.librenms.svc.cluster.local:8000",
			WebhookPath:        "/api/v1/services/librenms/webhook",
		}, nil
	}
	secrets, err := m.ensureSecretsLocked(nil)
	if err != nil {
		return nil, err
	}

	preview := ""
	if len(secrets.APIToken) >= 8 {
		preview = secrets.APIToken[:4] + "…" + secrets.APIToken[len(secrets.APIToken)-4:]
	} else if secrets.APIToken != "" {
		preview = libreNmsMaskedPlaceholder
	}

	out := &LibreNMSCredentialsSummary{
		Configured:         true,
		AdminUsername:      bundle.Config.AdminUsername,
		AdminEmail:         bundle.Config.AdminEmail,
		EndpointURL:        bundle.EndpointURL,
		InternalServiceURL: bundle.InternalServiceURL,
		WebhookPath:        "/api/v1/services/librenms/webhook",
		TokenPreview:       preview,
	}
	if reveal {
		out.APIToken = secrets.APIToken
		out.AdminPassword = secrets.AdminPassword
		out.WebhookSecret = secrets.WebhookSecret
	}
	return out, nil
}

// RecordWebhookAlert authenticates an inbound LibreNMS Alert Transport webhook and stores it in the ring buffer.
func (m *LibreNMSManager) RecordWebhookAlert(presentedSecret string, rawPayload []byte) (*LibreNMSWebhookAlert, error) {
	m.mu.Lock()
	secrets, err := m.ensureSecretsLocked(nil)
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	expected := strings.TrimSpace(secrets.WebhookSecret)
	presented := strings.TrimSpace(presentedSecret)
	if expected == "" || len(expected) != len(presented) || subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) != 1 {
		return nil, fmt.Errorf("unauthorized LibreNMS webhook secret")
	}

	var doc map[string]any
	if err := json.Unmarshal(rawPayload, &doc); err != nil {
		return nil, fmt.Errorf("invalid LibreNMS webhook payload: %w", err)
	}

	host := strings.TrimSpace(asStr(doc["hostname"]))
	if host == "" {
		host = strings.TrimSpace(asStr(doc["sysName"]))
	}
	if host == "" {
		host = strings.TrimSpace(asStr(doc["device_hostname"]))
	}
	if host == "" {
		host = strings.TrimSpace(asStr(doc["ip"]))
	}
	rule := strings.TrimSpace(asStr(doc["rule"]))
	if rule == "" {
		rule = strings.TrimSpace(asStr(doc["title"]))
	}
	if rule == "" {
		rule = "LibreNMS Alert"
	}
	sev := strings.ToLower(strings.TrimSpace(asStr(doc["severity"])))
	if sev == "" {
		sev = "critical"
	}
	stateNum := asInt(doc["state"])
	if _, hasState := doc["state"]; !hasState {
		stateNum = 1
	}
	ts := strings.TrimSpace(asStr(doc["timestamp"]))
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}
	portName := strings.TrimSpace(asStr(doc["port_name"]))
	if portName == "" {
		portName = strings.TrimSpace(asStr(doc["ifName"]))
	}
	msg := strings.TrimSpace(asStr(doc["msg"]))
	if msg == "" {
		msg = strings.TrimSpace(asStr(doc["message"]))
	}
	if msg == "" {
		msg = fmt.Sprintf("%s on %s", rule, host)
	}

	alert := LibreNMSWebhookAlert{
		ID:             fmt.Sprintf("wh-%d-%s-%s", time.Now().UTC().UnixMilli(), toNetBoxSlug(host), toNetBoxSlug(rule)),
		DeviceID:       asInt(doc["device_id"]),
		DeviceHostname: host,
		DeviceIP:       strings.TrimSpace(asStr(doc["ip"])),
		Rule:           rule,
		Severity:       sev,
		State:          stateNum,
		Timestamp:      ts,
		PortName:       portName,
		Message:        msg,
		Source:         "webhook",
	}

	m.mu.Lock()
	// Replace matching existing alert (host + rule + portName) or prepend newest; remove on resolved state==0
	filtered := make([]LibreNMSWebhookAlert, 0, len(m.webhookAlerts)+1)
	if stateNum != 0 {
		filtered = append(filtered, alert)
	}
	for _, existing := range m.webhookAlerts {
		if strings.EqualFold(existing.DeviceHostname, alert.DeviceHostname) &&
			strings.EqualFold(existing.Rule, alert.Rule) &&
			strings.EqualFold(existing.PortName, alert.PortName) {
			continue
		}
		filtered = append(filtered, existing)
		if len(filtered) >= libreNmsMaxWebhookAlerts {
			break
		}
	}
	m.webhookAlerts = filtered
	m.mu.Unlock()

	return &alert, nil
}

func (m *LibreNMSManager) ListWebhookAlerts() []LibreNMSWebhookAlert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LibreNMSWebhookAlert, len(m.webhookAlerts))
	copy(out, m.webhookAlerts)
	return out
}

// GetTopologySnapshot queries LibreNMS REST v0 APIs for devices, ports, LLDP/CDP/xDP links, FDB, ARP, health sensors, and alerts.
func (m *LibreNMSManager) GetTopologySnapshot(ctx context.Context, endpointOverride ...string) *LibreNMSTopologySnapshot {
	override := ""
	if len(endpointOverride) > 0 {
		override = endpointOverride[0]
	}
	webhookAlerts := m.ListWebhookAlerts()
	out := &LibreNMSTopologySnapshot{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Devices:       []LibreNMSDevice{},
		Ports:         []LibreNMSPort{},
		Links:         []LibreNMSLink{},
		FDB:           []LibreNMSFDBEntry{},
		ARP:           []LibreNMSARPEntry{},
		HealthSensors: []LibreNMSHealthSensor{},
		Alerts:        append([]LibreNMSWebhookAlert{}, webhookAlerts...),
		WebhookAlerts: webhookAlerts,
	}

	client, _, _, err := m.resolveClient(ctx, override)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Endpoint = client.baseURL

	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// 1. Devices
	_, devDoc, devErr := client.doJSON(reqCtx, http.MethodGet, "/api/v0/devices", nil)
	if devErr != nil {
		out.Error = fmt.Sprintf("LibreNMS API unreachable (%v)", devErr)
		return out
	}
	out.Available = true

	devHostByID := map[int]string{}
	if devList, ok := devDoc["devices"].([]any); ok {
		for _, item := range devList {
			d, ok := item.(map[string]any)
			if !ok {
				continue
			}
			id := asInt(d["device_id"])
			host := strings.TrimSpace(asStr(d["hostname"]))
			sysName := strings.TrimSpace(asStr(d["sysName"]))
			if host != "" {
				devHostByID[id] = host
			} else if sysName != "" {
				devHostByID[id] = sysName
			}
			out.Devices = append(out.Devices, LibreNMSDevice{
				DeviceID: id,
				Hostname: host,
				SysName:  sysName,
				IP:       strings.TrimSpace(asStr(d["ip"])),
				OS:       strings.TrimSpace(asStr(d["os"])),
				Hardware: strings.TrimSpace(asStr(d["hardware"])),
				Version:  strings.TrimSpace(asStr(d["version"])),
				Serial:   strings.TrimSpace(asStr(d["serial"])),
				Status:   asBoolFlex(d["status"]),
				Disabled: asBoolFlex(d["disabled"]),
				Location: strings.TrimSpace(asStr(d["location"])),
				Purpose:  strings.TrimSpace(asStr(d["purpose"])),
				Uptime:   asInt64(d["uptime"]),
			})
		}
	}

	// 2. Ports with rate, error counters, VLAN, MTU, MAC
	portByID := map[int]LibreNMSPort{}
	portCols := "port_id,device_id,ifIndex,ifName,ifDescr,ifAlias,ifOperStatus,ifAdminStatus,ifSpeed,ifInOctets_rate,ifOutOctets_rate,ifInErrors_delta,ifOutErrors_delta,ifVlan,ifMtu,ifPhysAddress,ifType"
	if _, pDoc, pErr := client.doJSON(reqCtx, http.MethodGet, "/api/v0/ports?columns="+portCols, nil); pErr == nil {
		if pList, ok := pDoc["ports"].([]any); ok {
			for _, item := range pList {
				p, ok := item.(map[string]any)
				if !ok {
					continue
				}
				pid := asInt(p["port_id"])
				did := asInt(p["device_id"])
				ifIdx := asInt(p["ifIndex"])
				ifName := strings.TrimSpace(asStr(p["ifName"]))
				if ifName == "" {
					ifName = strings.TrimSpace(asStr(p["ifDescr"]))
				}
				port := LibreNMSPort{
					PortID:        pid,
					DeviceID:      did,
					IfIndex:       ifIdx,
					DeviceHost:    devHostByID[did],
					IfName:        ifName,
					IfDescr:       strings.TrimSpace(asStr(p["ifDescr"])),
					IfAlias:       strings.TrimSpace(asStr(p["ifAlias"])),
					IfOperStatus:  strings.ToLower(strings.TrimSpace(asStr(p["ifOperStatus"]))),
					IfAdminStatus: strings.ToLower(strings.TrimSpace(asStr(p["ifAdminStatus"]))),
					IfSpeedBps:    asInt64(p["ifSpeed"]),
					InRateBps:     asFloat(p["ifInOctets_rate"]) * 8,
					OutRateBps:    asFloat(p["ifOutOctets_rate"]) * 8,
					InErrors:      asInt64(p["ifInErrors_delta"]),
					OutErrors:     asInt64(p["ifOutErrors_delta"]),
					IfVlan:        strings.TrimSpace(asStr(p["ifVlan"])),
					IfMtu:         asInt(p["ifMtu"]),
					IfPhysAddress: strings.TrimSpace(asStr(p["ifPhysAddress"])),
					IfType:        strings.TrimSpace(asStr(p["ifType"])),
				}
				portByID[pid] = port
				out.Ports = append(out.Ports, port)
			}
		}
	}

	// 3. LLDP / CDP / xDP Links
	if _, lDoc, lErr := client.doJSON(reqCtx, http.MethodGet, "/api/v0/resources/links", nil); lErr == nil {
		if lList, ok := lDoc["links"].([]any); ok {
			for _, item := range lList {
				l, ok := item.(map[string]any)
				if !ok {
					continue
				}
				localDevID := asInt(l["local_device_id"])
				localPortID := asInt(l["local_port_id"])
				remoteDevID := asInt(l["remote_device_id"])
				remotePortID := asInt(l["remote_port_id"])
				localPort := strings.TrimSpace(asStr(l["local_port"]))
				if localPort == "" {
					localPort = portByID[localPortID].IfName
				}
				remoteDev := strings.TrimSpace(asStr(l["remote_hostname"]))
				if remoteDev == "" && remoteDevID > 0 {
					remoteDev = devHostByID[remoteDevID]
				}
				remotePort := strings.TrimSpace(asStr(l["remote_port"]))
				if remotePort == "" && remotePortID > 0 {
					remotePort = portByID[remotePortID].IfName
				}
				proto := strings.TrimSpace(asStr(l["protocol"]))
				if proto == "" {
					proto = "lldp"
				}
				active := true
				if _, hasActive := l["active"]; hasActive {
					active = asBoolFlex(l["active"])
				}
				out.Links = append(out.Links, LibreNMSLink{
					ID:             asInt(l["id"]),
					LocalDeviceID:  localDevID,
					LocalDevice:    devHostByID[localDevID],
					LocalPortID:    localPortID,
					LocalPort:      localPort,
					RemoteDeviceID: remoteDevID,
					RemoteDevice:   remoteDev,
					RemotePortID:   remotePortID,
					RemotePort:     remotePort,
					Protocol:       strings.ToLower(proto),
					Active:         active,
				})
			}
		}
	}

	// 4. FDB & ARP tables (best-effort)
	if _, fDoc, fErr := client.doJSON(reqCtx, http.MethodGet, "/api/v0/resources/fdb", nil); fErr == nil {
		rawKey := "fdb"
		if _, ok := fDoc["ports_fdb"]; ok {
			rawKey = "ports_fdb"
		}
		if fList, ok := fDoc[rawKey].([]any); ok {
			for idx, item := range fList {
				if idx >= 1000 {
					break
				}
				f, ok := item.(map[string]any)
				if !ok {
					continue
				}
				out.FDB = append(out.FDB, LibreNMSFDBEntry{
					DeviceID: asInt(f["device_id"]),
					PortID:   asInt(f["port_id"]),
					VlanID:   asInt(f["vlan_id"]),
					MacAddr:  strings.ToLower(strings.TrimSpace(asStr(f["mac_address"]))),
				})
			}
		}
	}
	if _, aDoc, aErr := client.doJSON(reqCtx, http.MethodGet, "/api/v0/resources/ip/arp", nil); aErr == nil {
		if aList, ok := aDoc["arp"].([]any); ok {
			for idx, item := range aList {
				if idx >= 1000 {
					break
				}
				a, ok := item.(map[string]any)
				if !ok {
					continue
				}
				out.ARP = append(out.ARP, LibreNMSARPEntry{
					DeviceID:  asInt(a["device_id"]),
					PortID:    asInt(a["port_id"]),
					MacAddr:   strings.ToLower(strings.TrimSpace(asStr(a["mac_address"]))),
					IPAddress: strings.TrimSpace(asStr(a["ipv4_address"])),
				})
			}
		}
	}

	// 5. Active polled alerts
	if _, alDoc, alErr := client.doJSON(reqCtx, http.MethodGet, "/api/v0/alerts?state=1", nil); alErr == nil {
		if alList, ok := alDoc["alerts"].([]any); ok {
			for _, item := range alList {
				al, ok := item.(map[string]any)
				if !ok {
					continue
				}
				did := asInt(al["device_id"])
				host := strings.TrimSpace(asStr(al["hostname"]))
				if host == "" {
					host = devHostByID[did]
				}
				rule := strings.TrimSpace(asStr(al["name"]))
				if rule == "" {
					rule = strings.TrimSpace(asStr(al["rule"]))
				}
				if rule == "" {
					rule = "Alert #" + strconv.Itoa(asInt(al["rule_id"]))
				}
				sev := strings.ToLower(strings.TrimSpace(asStr(al["severity"])))
				if sev == "" {
					sev = "warning"
				}
				out.Alerts = append(out.Alerts, LibreNMSWebhookAlert{
					ID:             "poll-" + strconv.Itoa(asInt(al["id"])),
					DeviceID:       did,
					DeviceHostname: host,
					Rule:           rule,
					Severity:       sev,
					State:          asInt(al["state"]),
					Timestamp:      strings.TrimSpace(asStr(al["timestamp"])),
					Message:        strings.TrimSpace(asStr(al["info"])),
					Source:         "polled",
				})
			}
		}
	}

	// 6. Health / DOM optical sensors (bounded to first 16 active devices)
	limitDevs := len(out.Devices)
	if limitDevs > 16 {
		limitDevs = 16
	}
	for i := 0; i < limitDevs; i++ {
		d := out.Devices[i]
		if d.DeviceID == 0 || d.Disabled {
			continue
		}
		if _, hDoc, hErr := client.doJSON(reqCtx, http.MethodGet, fmt.Sprintf("/api/v0/devices/%d/health", d.DeviceID), nil); hErr == nil {
			if sensors, ok := hDoc["graphs"].([]any); ok {
				for _, sAny := range sensors {
					sMap, ok := sAny.(map[string]any)
					if !ok {
						continue
					}
					descr := strings.TrimSpace(asStr(sMap["desc"]))
					class := strings.TrimSpace(asStr(sMap["name"]))
					if class == "" && descr == "" {
						continue
					}
					cur := asFloat(sMap["sensor_current"])
					high := asFloat(sMap["sensor_limit"])
					low := asFloat(sMap["sensor_limit_low"])
					alerted := (high > 0 && cur > high) || (low != 0 && cur < low)
					out.HealthSensors = append(out.HealthSensors, LibreNMSHealthSensor{
						DeviceID:  d.DeviceID,
						Class:     class,
						Descr:     descr,
						Current:   cur,
						HighLimit: high,
						LowLimit:  low,
						Alerted:   alerted,
					})
				}
			}
		}
	}

	return out
}

func (m *LibreNMSManager) buildSnmpDevicePayload(hostname string, port int, bundle *LibreNMSRuntimeBundle, sec *libreNmsHostSecrets) map[string]any {
	payload := map[string]any{
		"hostname": hostname,
		"port":     port,
	}
	snmpCfg := bundle.Config.SnmpDefaults
	if snmpCfg.Version == "v3" {
		payload["snmpver"] = "v3"
		if snmpCfg.V3AuthLevel != "" {
			payload["authlevel"] = snmpCfg.V3AuthLevel
		}
		if snmpCfg.V3AuthUser != "" {
			payload["authname"] = snmpCfg.V3AuthUser
		}
		if snmpCfg.V3AuthAlgo != "" {
			payload["authalgo"] = snmpCfg.V3AuthAlgo
		}
		if sec != nil && sec.SnmpV3AuthPass != "" {
			payload["authpass"] = sec.SnmpV3AuthPass
		}
		if snmpCfg.V3CryptoAlgo != "" {
			payload["cryptoalgo"] = snmpCfg.V3CryptoAlgo
		}
		if sec != nil && sec.SnmpV3CryptoPass != "" {
			payload["cryptopass"] = sec.SnmpV3CryptoPass
		}
	} else {
		payload["snmpver"] = "v2c"
		comm := "public"
		if sec != nil && sec.SnmpCommunity != "" {
			comm = sec.SnmpCommunity
		} else if snmpCfg.Community != "" {
			comm = snmpCfg.Community
		}
		payload["community"] = comm
	}
	return payload
}

// SyncDevices dry-runs or enrolls configured Axonwall hosts, HA peer, fleet satellites, and topology peers into LibreNMS.
func (m *LibreNMSManager) SyncDevices(ctx context.Context, req *LibreNMSSyncRequest) (*LibreNMSSyncResult, error) {
	if req == nil {
		req = &LibreNMSSyncRequest{}
	}
	client, bundle, sec, err := m.resolveClient(ctx, req.EndpointOverride)
	if err != nil {
		return nil, err
	}

	res := &LibreNMSSyncResult{
		Success:   true,
		DryRun:    req.DryRun,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Endpoint:  client.baseURL,
		Subnets:   len(bundle.EnrollmentPlan.DiscoverySubnets),
	}

	existing := map[string]bool{}
	snap := m.GetTopologySnapshot(ctx, client.baseURL)
	if snap.Available {
		for _, d := range snap.Devices {
			if d.Hostname != "" {
				existing[strings.ToLower(strings.TrimSpace(d.Hostname))] = true
			}
			if d.IP != "" {
				existing[strings.ToLower(strings.TrimSpace(d.IP))] = true
			}
		}
	}

	for _, t := range bundle.EnrollmentPlan.Targets {
		host := strings.TrimSpace(t.Hostname)
		if host == "" {
			continue
		}
		if existing[strings.ToLower(host)] {
			res.Existing++
			continue
		}
		if req.DryRun {
			res.Enrolled++
			continue
		}
		port := t.Port
		if port <= 0 {
			port = bundle.Config.SnmpDefaults.Port
		}
		if port <= 0 {
			port = 161
		}
		payload := m.buildSnmpDevicePayload(host, port, bundle, sec)
		if t.DisplayName != "" {
			payload["display"] = t.DisplayName
		}
		if t.SysRole != "" {
			payload["purpose"] = t.SysRole
		}
		if _, _, dErr := client.doJSON(ctx, http.MethodPost, "/api/v0/devices", payload); dErr != nil {
			res.Failed++
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s (%s): %v", t.DisplayName, host, dErr))
		} else {
			res.Enrolled++
			existing[strings.ToLower(host)] = true
		}
	}

	if res.Failed > 0 && res.Enrolled == 0 && res.Existing == 0 {
		res.Success = false
	}

	if !req.DryRun {
		m.mu.Lock()
		if encoded, encErr := json.MarshalIndent(res, "", "  "); encErr == nil {
			_ = writeFilesAtomic([]atomicFileWrite{
				{path: filepath.Join(m.configDir, "last-sync.json"), content: string(encoded) + "\n", perm: 0640},
			})
		}
		m.mu.Unlock()
	}

	return res, nil
}

// SyncWithNetBox coordinates explicit push/pull/preview between LibreNMS discovered hardware/LLDP cables and NetBox DCIM.
func (m *LibreNMSManager) SyncWithNetBox(ctx context.Context, req *LibreNMSNetBoxSyncRequest) (*LibreNMSNetBoxSyncResult, error) {
	if req == nil {
		req = &LibreNMSNetBoxSyncRequest{Action: "preview", DryRun: true}
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "preview"
	}
	dryRun := req.DryRun || action == "preview"

	out := &LibreNMSNetBoxSyncResult{
		Success:   true,
		Action:    action,
		DryRun:    dryRun,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if m.netboxManager == nil {
		return nil, fmt.Errorf("NetBox manager is not initialized on this host")
	}

	if action == "pull" {
		client, bundle, sec, err := m.resolveClient(ctx, req.EndpointOverride)
		if err != nil {
			return nil, err
		}
		out.LibreNMSEndpoint = client.baseURL

		nbSnap := m.netboxManager.ExportInventory(ctx, req.NetBoxOverride)
		out.NetBoxEndpoint = nbSnap.Endpoint
		if !nbSnap.Available {
			return nil, fmt.Errorf("NetBox inventory unavailable: %s", nbSnap.Error)
		}
		lnmsSnap := m.GetTopologySnapshot(ctx, client.baseURL)
		existing := map[string]bool{}
		for _, d := range lnmsSnap.Devices {
			existing[strings.ToLower(d.Hostname)] = true
			if d.IP != "" {
				existing[strings.ToLower(d.IP)] = true
			}
		}

		pullRes := &LibreNMSSyncResult{
			Success:   true,
			DryRun:    dryRun,
			Timestamp: out.Timestamp,
			Endpoint:  client.baseURL,
		}
		for _, dev := range nbSnap.Devices {
			target := strings.TrimSpace(strings.Split(dev.PrimaryIP, "/")[0])
			if target == "" {
				target = strings.TrimSpace(dev.Name)
			}
			if target == "" {
				continue
			}
			out.DevicesQueued++
			if existing[strings.ToLower(target)] || existing[strings.ToLower(dev.Name)] {
				pullRes.Existing++
				continue
			}
			if dryRun {
				pullRes.Enrolled++
				continue
			}
			payload := m.buildSnmpDevicePayload(target, bundle.Config.SnmpDefaults.Port, bundle, sec)
			payload["display"] = dev.Name
			if dev.Role != "" {
				payload["purpose"] = dev.Role
			}
			if _, _, dErr := client.doJSON(ctx, http.MethodPost, "/api/v0/devices", payload); dErr != nil {
				pullRes.Failed++
				pullRes.Warnings = append(pullRes.Warnings, fmt.Sprintf("%s: %v", dev.Name, dErr))
			} else {
				pullRes.Enrolled++
			}
		}
		out.PullResult = pullRes
		out.Warnings = append(out.Warnings, pullRes.Warnings...)
		return out, nil
	}

	// Default: "preview" or "push" (LibreNMS devices & LLDP/CDP links -> NetBox DCIM)
	snap := m.GetTopologySnapshot(ctx, req.EndpointOverride)
	out.LibreNMSEndpoint = snap.Endpoint
	if !snap.Available {
		return nil, fmt.Errorf("LibreNMS topology unavailable: %s", snap.Error)
	}

	var nbDevs []NetBoxUpsertDeviceSpec
	seenDevs := map[string]bool{}
	for _, d := range snap.Devices {
		name := strings.TrimSpace(d.SysName)
		if name == "" {
			name = strings.TrimSpace(d.Hostname)
		}
		if name == "" || seenDevs[strings.ToLower(name)] {
			continue
		}
		seenDevs[strings.ToLower(name)] = true
		status := "active"
		if !d.Status {
			status = "offline"
		}
		nbDevs = append(nbDevs, NetBoxUpsertDeviceSpec{
			Name:      name,
			Role:      "network-device",
			Model:     d.Hardware,
			Mfg:       d.OS,
			PrimaryIP: d.IP,
			Status:    status,
			Comments:  fmt.Sprintf("Synced from LibreNMS (OS=%s Version=%s Serial=%s)", d.OS, d.Version, d.Serial),
		})
	}

	var nbCables []NetBoxUpsertCableSpec
	seenCables := map[string]bool{}
	for _, link := range snap.Links {
		aDev := strings.TrimSpace(link.LocalDevice)
		aPort := strings.TrimSpace(link.LocalPort)
		bDev := strings.TrimSpace(link.RemoteDevice)
		bPort := strings.TrimSpace(link.RemotePort)
		if aDev == "" || aPort == "" || bDev == "" || bPort == "" {
			continue
		}
		key := canonicalCableKey(aDev, aPort, bDev, bPort)
		if seenCables[key] {
			continue
		}
		seenCables[key] = true
		nbCables = append(nbCables, NetBoxUpsertCableSpec{
			ADevice:    aDev,
			AInterface: aPort,
			BDevice:    bDev,
			BInterface: bPort,
			Status:     "connected",
			Comments:   fmt.Sprintf("Auto-discovered via LibreNMS (%s)", strings.ToUpper(link.Protocol)),
		})
	}

	out.DevicesQueued = len(nbDevs)
	out.CablesQueued = len(nbCables)
	nbRes, nbErr := m.netboxManager.UpsertCablesAndDevices(ctx, &NetBoxCablesSyncRequest{
		DryRun:           dryRun,
		EndpointOverride: req.NetBoxOverride,
		Devices:          nbDevs,
		Cables:           nbCables,
		OverwriteLabels:  req.OverwriteLabels,
	})
	if nbErr != nil {
		return nil, nbErr
	}
	out.NetBoxEndpoint = nbRes.Endpoint
	out.NetBoxResult = nbRes
	out.Warnings = append(out.Warnings, nbRes.Warnings...)
	return out, nil
}
