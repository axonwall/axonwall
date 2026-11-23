package engine

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const netBoxMaskedPlaceholder = "********"

type NetBoxSyncFlags struct {
	Enabled             bool `json:"enabled"`
	AutoSyncOnApply     bool `json:"autoSyncOnApply"`
	SyncInterfaces      bool `json:"syncInterfaces"`
	SyncVlans           bool `json:"syncVlans"`
	SyncVrfs            bool `json:"syncVrfs"`
	SyncPrefixes        bool `json:"syncPrefixes"`
	SyncDhcpLeases      bool `json:"syncDhcpLeases"`
	SyncVirtualIps      bool `json:"syncVirtualIps"`
	SyncVirtualMachines bool `json:"syncVirtualMachines"`
	SyncK3sNodes        bool `json:"syncK3sNodes"`
}

type NetBoxConfigMetadata struct {
	Namespace         string          `json:"namespace"`
	Domain            string          `json:"domain"`
	ServicePort       int             `json:"servicePort"`
	SuperuserUsername string          `json:"superuserUsername"`
	SuperuserEmail    string          `json:"superuserEmail"`
	ExternalUrl       string          `json:"externalUrl,omitempty"`
	SiteName          string          `json:"siteName"`
	SiteSlug          string          `json:"siteSlug"`
	Sync              NetBoxSyncFlags `json:"sync"`
}

type NetBoxPlannedVrf struct {
	Name          string `json:"name"`
	RD            string `json:"rd,omitempty"`
	EnforceUnique bool   `json:"enforceUnique"`
	Description   string `json:"description"`
}

type NetBoxPlannedVlan struct {
	VID             int    `json:"vid"`
	Name            string `json:"name"`
	ParentInterface string `json:"parentInterface"`
	Description     string `json:"description"`
}

type NetBoxPlannedInterface struct {
	Name        string `json:"name"`
	Device      string `json:"device"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	MTU         int    `json:"mtu"`
	Role        string `json:"role"`
	IPv4Address string `json:"ipv4Address,omitempty"`
	IPv6Address string `json:"ipv6Address,omitempty"`
	Description string `json:"description"`
}

type NetBoxPlannedPrefix struct {
	Prefix      string `json:"prefix"`
	Family      int    `json:"family"`
	VRF         string `json:"vrf,omitempty"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

type NetBoxPlannedIpAddress struct {
	Address       string `json:"address"`
	VRF           string `json:"vrf,omitempty"`
	InterfaceName string `json:"interfaceName,omitempty"`
	Role          string `json:"role,omitempty"`
	Status        string `json:"status"`
	DNSName       string `json:"dnsName,omitempty"`
	Description   string `json:"description"`
}

type NetBoxPlannedVirtualMachine struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	VCPUs     int    `json:"vcpus"`
	MemoryMb  int    `json:"memoryMb"`
	DiskGb    int    `json:"diskGb"`
	Status    string `json:"status"`
	PrimaryIP string `json:"primaryIp,omitempty"`
	Comments  string `json:"comments"`
}

type NetBoxSyncPlanSummary struct {
	VrfsCount            int `json:"vrfsCount"`
	VlansCount           int `json:"vlansCount"`
	InterfacesCount      int `json:"interfacesCount"`
	PrefixesCount        int `json:"prefixesCount"`
	IpAddressesCount     int `json:"ipAddressesCount"`
	VirtualMachinesCount int `json:"virtualMachinesCount"`
	TotalObjects         int `json:"totalObjects"`
}

type NetBoxSyncPlan struct {
	Site struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"site"`
	Device struct {
		Hostname  string `json:"hostname"`
		Domain    string `json:"domain"`
		PrimaryIP string `json:"primaryIp,omitempty"`
		SiteSlug  string `json:"siteSlug"`
	} `json:"device"`
	VRFs            []NetBoxPlannedVrf            `json:"vrfs"`
	VLANs           []NetBoxPlannedVlan           `json:"vlans"`
	Interfaces      []NetBoxPlannedInterface      `json:"interfaces"`
	Prefixes        []NetBoxPlannedPrefix         `json:"prefixes"`
	IPAddresses     []NetBoxPlannedIpAddress      `json:"ipAddresses"`
	VirtualMachines []NetBoxPlannedVirtualMachine `json:"virtualMachines"`
	Summary         NetBoxSyncPlanSummary         `json:"summary"`
}

type NetBoxRuntimeBundle struct {
	Enabled            bool                 `json:"enabled"`
	K3sDependencyMet   bool                 `json:"k3sDependencyMet"`
	Config             NetBoxConfigMetadata `json:"config"`
	Namespace          string               `json:"namespace"`
	Domain             string               `json:"domain"`
	EndpointURL        string               `json:"endpointUrl"`
	InternalServiceURL string               `json:"internalServiceUrl"`
	K3sManifestsYaml   string               `json:"k3sManifestsYaml"`
	UnboundOverrides   string               `json:"unboundOverrides"`
	SyncPlan           NetBoxSyncPlan       `json:"syncPlan"`
	APIToken           string               `json:"apiToken,omitempty"`
	SuperuserPassword  string               `json:"superuserPassword,omitempty"`
}

type netBoxHostSecrets struct {
	DBPassword        string `json:"dbPassword"`
	RedisPassword     string `json:"redisPassword"`
	SecretKey         string `json:"secretKey"`
	SuperuserPassword string `json:"superuserPassword"`
	APIToken          string `json:"apiToken"`
}

type NetBoxPodStatus = K3sAppPodStatus

type NetBoxExportedDevice struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role,omitempty"`
	DeviceType string `json:"deviceType,omitempty"`
	Site       string `json:"site,omitempty"`
	Rack       string `json:"rack,omitempty"`
	PrimaryIP  string `json:"primaryIp,omitempty"`
	Status     string `json:"status,omitempty"`
	Comments   string `json:"comments,omitempty"`
}

type NetBoxExportedInterface struct {
	ID          int    `json:"id"`
	DeviceID    int    `json:"deviceId"`
	DeviceName  string `json:"deviceName"`
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Enabled     bool   `json:"enabled"`
	MTU         int    `json:"mtu,omitempty"`
	MACAddress  string `json:"macAddress,omitempty"`
	Description string `json:"description,omitempty"`
}

type NetBoxExportedCable struct {
	ID         int     `json:"id"`
	ADevice    string  `json:"aDevice"`
	AInterface string  `json:"aInterface"`
	BDevice    string  `json:"bDevice"`
	BInterface string  `json:"bInterface"`
	Type       string  `json:"type,omitempty"`
	Status     string  `json:"status,omitempty"`
	Label      string  `json:"label,omitempty"`
	Color      string  `json:"color,omitempty"`
	Length     float64 `json:"length,omitempty"`
	LengthUnit string  `json:"lengthUnit,omitempty"`
	Comments   string  `json:"comments,omitempty"`
}

type NetBoxExportedRack struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Site    string `json:"site,omitempty"`
	UHeight int    `json:"uHeight,omitempty"`
}

type NetBoxInventorySnapshot struct {
	Available  bool                      `json:"available"`
	Endpoint   string                    `json:"endpoint,omitempty"`
	Timestamp  string                    `json:"timestamp"`
	Sites      []string                  `json:"sites"`
	Racks      []NetBoxExportedRack      `json:"racks"`
	Devices    []NetBoxExportedDevice    `json:"devices"`
	Interfaces []NetBoxExportedInterface `json:"interfaces"`
	Cables     []NetBoxExportedCable     `json:"cables"`
	Prefixes   []string                  `json:"prefixes"`
	VLANs      []int                     `json:"vlans"`
	Error      string                    `json:"error,omitempty"`
}

type NetBoxUpsertDeviceSpec struct {
	Name      string `json:"name"`
	Role      string `json:"role,omitempty"`
	Model     string `json:"model,omitempty"`
	Mfg       string `json:"mfg,omitempty"`
	Site      string `json:"site,omitempty"`
	PrimaryIP string `json:"primaryIp,omitempty"`
	Status    string `json:"status,omitempty"`
	Comments  string `json:"comments,omitempty"`
}

type NetBoxUpsertCableSpec struct {
	ADevice    string  `json:"aDevice"`
	AInterface string  `json:"aInterface"`
	BDevice    string  `json:"bDevice"`
	BInterface string  `json:"bInterface"`
	Type       string  `json:"type,omitempty"`
	Status     string  `json:"status,omitempty"`
	Label      string  `json:"label,omitempty"`
	Color      string  `json:"color,omitempty"`
	Length     float64 `json:"length,omitempty"`
	LengthUnit string  `json:"lengthUnit,omitempty"`
	Comments   string  `json:"comments,omitempty"`
}

type NetBoxCableConflict struct {
	Key         string `json:"key"`
	Field       string `json:"field"`
	AxonwallVal string `json:"axonwallVal"`
	NetBoxVal   string `json:"netboxVal"`
	Resolution  string `json:"resolution,omitempty"`
}

type NetBoxCablesSyncRequest struct {
	DryRun           bool                     `json:"dryRun"`
	EndpointOverride string                   `json:"endpointOverride,omitempty"`
	Devices          []NetBoxUpsertDeviceSpec `json:"devices,omitempty"`
	Cables           []NetBoxUpsertCableSpec  `json:"cables,omitempty"`
	OverwriteLabels  bool                     `json:"overwriteLabels,omitempty"`
}

type NetBoxCablesSyncResult struct {
	Success    bool                  `json:"success"`
	DryRun     bool                  `json:"dryRun"`
	Timestamp  string                `json:"timestamp"`
	Endpoint   string                `json:"endpoint"`
	Devices    NetBoxSyncCounts      `json:"devices"`
	Interfaces NetBoxSyncCounts      `json:"interfaces"`
	Cables     NetBoxSyncCounts      `json:"cables"`
	Conflicts  []NetBoxCableConflict `json:"conflicts"`
	Warnings   []string              `json:"warnings,omitempty"`
	Error      string                `json:"error,omitempty"`
}

type NetBoxSyncCounts struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
}

type NetBoxSyncResult struct {
	Success         bool             `json:"success"`
	DryRun          bool             `json:"dryRun"`
	Timestamp       string           `json:"timestamp"`
	Endpoint        string           `json:"endpoint"`
	DevicesSynced   int              `json:"devicesSynced"`
	VRFs            NetBoxSyncCounts `json:"vrfs"`
	VLANs           NetBoxSyncCounts `json:"vlans"`
	Interfaces      NetBoxSyncCounts `json:"interfaces"`
	Prefixes        NetBoxSyncCounts `json:"prefixes"`
	IPAddresses     NetBoxSyncCounts `json:"ipAddresses"`
	VirtualMachines NetBoxSyncCounts `json:"virtualMachines"`
	Warnings        []string         `json:"warnings,omitempty"`
	Error           string           `json:"error,omitempty"`
}

type NetBoxStatus struct {
	Enabled            bool                   `json:"enabled"`
	K3sDependencyMet   bool                   `json:"k3sDependencyMet"`
	K3sReady           bool                   `json:"k3sReady"`
	ManifestPresent    bool                   `json:"manifestPresent"`
	LDAPBound          bool                   `json:"ldapBound"`
	APIReachable       bool                   `json:"apiReachable"`
	NetBoxVersion      string                 `json:"netboxVersion,omitempty"`
	Namespace          string                 `json:"namespace"`
	Domain             string                 `json:"domain"`
	EndpointURL        string                 `json:"endpointUrl"`
	InternalServiceURL string                 `json:"internalServiceUrl"`
	ClusterIP          string                 `json:"clusterIp,omitempty"`
	SiteName           string                 `json:"siteName"`
	SiteSlug           string                 `json:"siteSlug"`
	Pods               []NetBoxPodStatus      `json:"pods"`
	PodReadyCount      int                    `json:"podReadyCount"`
	PodTotalCount      int                    `json:"podTotalCount"`
	LastSync           *NetBoxSyncResult      `json:"lastSync,omitempty"`
	PlannedSummary     *NetBoxSyncPlanSummary `json:"plannedSummary,omitempty"`
	StatusError        string                 `json:"statusError,omitempty"`
}

type NetBoxCredentialsSummary struct {
	Configured         bool   `json:"configured"`
	SuperuserUsername  string `json:"superuserUsername"`
	SuperuserEmail     string `json:"superuserEmail"`
	EndpointURL        string `json:"endpointUrl"`
	InternalServiceURL string `json:"internalServiceUrl"`
	TokenPreview       string `json:"tokenPreview,omitempty"`
	APIToken           string `json:"apiToken,omitempty"`
	SuperuserPassword  string `json:"superuserPassword,omitempty"`
}

type NetBoxSyncRequest struct {
	DryRun           bool   `json:"dryRun"`
	EndpointOverride string `json:"endpointOverride,omitempty"`
}

type NetBoxManager struct {
	mu              sync.Mutex
	configDir       string
	manifestDir     string
	ldapBindingPath string
	keaLeasesPath   string
	k3sManager      *K3sManager
	virtManager     *VirtManager
	httpClient      *http.Client
	kubectlRunner   func(ctx context.Context, args ...string) ([]byte, error)
}

func NewNetBoxManager(configDir string, k3sManager *K3sManager, virtManager *VirtManager) *NetBoxManager {
	return &NetBoxManager{
		configDir:       configDir,
		manifestDir:     k3sServerManifestDir,
		ldapBindingPath: filepath.Join(LDAPPluginClientsDir, "netbox.json"),
		keaLeasesPath:   "/var/lib/kea/kea-leases4.csv",
		k3sManager:      k3sManager,
		virtManager:     virtManager,
		httpClient:      newInternalK3sHTTPClient(8 * time.Second),
	}
}

func (m *NetBoxManager) manifestPath() string {
	dir := m.manifestDir
	if dir == "" {
		dir = k3sServerManifestDir
	}
	return filepath.Join(dir, "axonwall-netbox.yaml")
}

func (m *NetBoxManager) loadSavedBundle() (*NetBoxRuntimeBundle, error) {
	data, err := os.ReadFile(filepath.Join(m.configDir, "config.json"))
	if err != nil {
		return nil, err
	}
	var bundle NetBoxRuntimeBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func (m *NetBoxManager) ensureSecretsLocked(overrideToken, overrideSuperuserPass string) (*netBoxHostSecrets, error) {
	if err := os.MkdirAll(m.configDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create netbox config dir %q: %w", m.configDir, err)
	}
	secPath := filepath.Join(m.configDir, "secrets.json")
	sec := &netBoxHostSecrets{}
	loaded := false
	if raw, err := os.ReadFile(secPath); err == nil {
		if err := json.Unmarshal(raw, sec); err == nil {
			loaded = true
		}
	}

	dirty := !loaded
	if sec.DBPassword == "" {
		val, err := randomHexToken(16)
		if err != nil {
			return nil, err
		}
		sec.DBPassword = val
		dirty = true
	}
	if sec.RedisPassword == "" {
		val, err := randomHexToken(16)
		if err != nil {
			return nil, err
		}
		sec.RedisPassword = val
		dirty = true
	}
	if len(sec.SecretKey) < 50 {
		val, err := randomHexToken(32) // 64 hex chars (>= Django's 50-char SECRET_KEY floor)
		if err != nil {
			return nil, err
		}
		sec.SecretKey = val
		dirty = true
	}
	if sec.SuperuserPassword == "" {
		val, err := randomHexToken(12)
		if err != nil {
			return nil, err
		}
		sec.SuperuserPassword = val
		dirty = true
	}
	if sec.APIToken == "" {
		val, err := randomHexToken(20) // 40 hex chars (NetBox v4 API token length)
		if err != nil {
			return nil, err
		}
		sec.APIToken = val
		dirty = true
	}

	cleanToken := strings.TrimSpace(overrideToken)
	if cleanToken != "" && cleanToken != netBoxMaskedPlaceholder && cleanToken != sec.APIToken {
		sec.APIToken = cleanToken
		dirty = true
	}
	cleanPass := strings.TrimSpace(overrideSuperuserPass)
	if cleanPass != "" && cleanPass != netBoxMaskedPlaceholder && cleanPass != sec.SuperuserPassword {
		sec.SuperuserPassword = cleanPass
		dirty = true
	}

	if dirty {
		encoded, err := json.MarshalIndent(sec, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := writeFilesAtomic([]atomicFileWrite{
			{path: secPath, content: string(encoded) + "\n", perm: 0600},
		}); err != nil {
			return nil, fmt.Errorf("failed to persist netbox secrets: %w", err)
		}
	}

	return sec, nil
}

func (m *NetBoxManager) readLDAPBindPassword() string {
	return readPluginLDAPBindPasswordFromFile(m.ldapBindingPath, "netbox")
}

func (m *NetBoxManager) ApplyConfig(rawJSON []byte) error {
	var bundle NetBoxRuntimeBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return fmt.Errorf("invalid netbox runtime bundle json: %w", err)
	}

	sanitizedBundle := bundle
	sanitizedBundle.APIToken = ""
	sanitizedBundle.SuperuserPassword = ""
	sanitizedBundle.K3sManifestsYaml = ""
	sanitizedBytes, err := json.MarshalIndent(sanitizedBundle, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode sanitized netbox config: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.configDir, 0750); err != nil {
		return fmt.Errorf("failed to create netbox config dir %q: %w", m.configDir, err)
	}

	mPath := m.manifestPath()
	if !bundle.Enabled || !bundle.K3sDependencyMet || strings.TrimSpace(bundle.K3sManifestsYaml) == "" {
		if err := removeFileIfExists(mPath); err != nil {
			return fmt.Errorf("failed to remove stale netbox manifest %q: %w", mPath, err)
		}
		return writeFilesAtomic([]atomicFileWrite{
			{path: filepath.Join(m.configDir, "config.json"), content: string(sanitizedBytes) + "\n", perm: 0600},
		})
	}

	secrets, err := m.ensureSecretsLocked(bundle.APIToken, bundle.SuperuserPassword)
	if err != nil {
		return err
	}
	ldapBindPass := m.readLDAPBindPassword()

	replacer := strings.NewReplacer(
		`"__AXONWALL_NETBOX_DB_PASSWORD__"`, strconv.Quote(secrets.DBPassword),
		`"__AXONWALL_NETBOX_REDIS_PASSWORD__"`, strconv.Quote(secrets.RedisPassword),
		`"__AXONWALL_NETBOX_SECRET_KEY__"`, strconv.Quote(secrets.SecretKey),
		`"__AXONWALL_NETBOX_SUPERUSER_PASSWORD__"`, strconv.Quote(secrets.SuperuserPassword),
		`"__AXONWALL_NETBOX_API_TOKEN__"`, strconv.Quote(secrets.APIToken),
		`"__AXONWALL_NETBOX_LDAP_BIND_PASSWORD__"`, strconv.Quote(ldapBindPass),
	)
	renderedManifest := replacer.Replace(bundle.K3sManifestsYaml)

	// Security invariant: validate rendered YAML BEFORE touching any files on disk
	if err := validateK3sManifest(renderedManifest); err != nil {
		return fmt.Errorf("netbox bundle rejected: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(mPath), 0755); err != nil {
		return fmt.Errorf("failed to create netbox manifest dir %q: %w", filepath.Dir(mPath), err)
	}

	writes := []atomicFileWrite{
		{path: filepath.Join(m.configDir, "config.json"), content: string(sanitizedBytes) + "\n", perm: 0600},
		{path: mPath, content: renderedManifest, perm: 0600},
	}
	if err := writeFilesAtomic(writes); err != nil {
		return err
	}

	slog.Info("Reconciled NetBox DCIM & IPAM K3s deployment manifests", "namespace", bundle.Namespace, "domain", bundle.Domain)

	if bundle.Config.Sync.Enabled && bundle.Config.Sync.AutoSyncOnApply {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if _, syncErr := m.SyncInventory(ctx, &NetBoxSyncRequest{DryRun: false}); syncErr != nil {
				slog.Warn("NetBox auto-sync after apply did not complete yet", "error", syncErr)
			}
		}()
	}

	return nil
}

func (m *NetBoxManager) runKubectl(ctx context.Context, args ...string) ([]byte, error) {
	return runPluginKubectl(ctx, m.kubectlRunner, args...)
}

func validateNetBoxEndpointURL(raw string) (string, error) {
	return validatePluginHTTPURL(raw, "netbox")
}

func (m *NetBoxManager) inspectK3sResources(ctx context.Context, namespace string) ([]NetBoxPodStatus, string) {
	if namespace == "" {
		namespace = "netbox"
	}
	return inspectK3sAppPodsAndService(ctx, m.kubectlRunner, namespace, "netbox")
}

func (m *NetBoxManager) resolveReachableBaseURL(ctx context.Context, bundle *NetBoxRuntimeBundle, clusterIP string) string {
	if clusterIP != "" {
		port := bundle.Config.ServicePort
		if port <= 0 {
			port = 8080
		}
		return fmt.Sprintf("http://%s:%d", clusterIP, port)
	}
	if strings.TrimSpace(bundle.EndpointURL) != "" {
		return strings.TrimRight(bundle.EndpointURL, "/")
	}
	if strings.TrimSpace(bundle.InternalServiceURL) != "" {
		return strings.TrimRight(bundle.InternalServiceURL, "/")
	}
	return "http://netbox.netbox.svc.cluster.local:8080"
}

func (m *NetBoxManager) probeNetBoxAPI(ctx context.Context, baseURL, token string) (bool, string, error) {
	validBase, err := validateNetBoxEndpointURL(baseURL)
	if err != nil {
		return false, "", err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, validBase+"/api/status/", nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Token "+token)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, "", fmt.Errorf("NetBox /api/status/ returned HTTP %d", resp.StatusCode)
	}
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	ver, _ := payload["netbox-version"].(string)
	return true, ver, nil
}

func (m *NetBoxManager) GetStatus(ctx context.Context) NetBoxStatus {
	st := NetBoxStatus{
		Namespace:          "netbox",
		Domain:             "netbox.axonwall.local",
		EndpointURL:        "https://netbox.axonwall.local",
		InternalServiceURL: "http://netbox.netbox.svc.cluster.local:8080",
		SiteName:           "Axonwall Appliance",
		SiteSlug:           "axonwall-appliance",
		Pods:               []NetBoxPodStatus{},
	}

	if _, err := os.Stat(m.manifestPath()); err == nil {
		st.ManifestPresent = true
	}
	ldapPath := m.ldapBindingPath
	if ldapPath == "" {
		ldapPath = filepath.Join(LDAPPluginClientsDir, "netbox.json")
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
	var token string
	if sec, err := m.ensureSecretsLocked("", ""); err == nil {
		token = sec.APIToken
	}
	if lastRaw, err := os.ReadFile(filepath.Join(m.configDir, "last-sync.json")); err == nil {
		var lr NetBoxSyncResult
		if json.Unmarshal(lastRaw, &lr) == nil {
			st.LastSync = &lr
		}
	}
	m.mu.Unlock()

	if loadErr != nil || bundle == nil {
		return st
	}

	st.Enabled = bundle.Enabled
	if bundle.K3sDependencyMet {
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
	if bundle.Config.SiteName != "" {
		st.SiteName = bundle.Config.SiteName
	}
	if bundle.Config.SiteSlug != "" {
		st.SiteSlug = bundle.Config.SiteSlug
	}
	summaryCopy := bundle.SyncPlan.Summary
	st.PlannedSummary = &summaryCopy

	if st.Enabled && st.K3sReady {
		pods, clusterIP := m.inspectK3sResources(ctx, st.Namespace)
		st.Pods = pods
		st.ClusterIP = clusterIP
		st.PodTotalCount = len(pods)
		for _, p := range pods {
			if p.Ready {
				st.PodReadyCount++
			}
		}
		probeBase := m.resolveReachableBaseURL(ctx, bundle, clusterIP)
		if ok, ver, err := m.probeNetBoxAPI(ctx, probeBase, token); ok {
			st.APIReachable = true
			st.NetBoxVersion = ver
		} else if bundle.EndpointURL != "" && probeBase != bundle.EndpointURL {
			if ok2, ver2, err2 := m.probeNetBoxAPI(ctx, bundle.EndpointURL, token); ok2 {
				st.APIReachable = true
				st.NetBoxVersion = ver2
			} else if err2 != nil {
				st.StatusError = err2.Error()
			}
		} else if err != nil {
			st.StatusError = err.Error()
		}
	}

	return st
}

func (m *NetBoxManager) GetBootstrapCredentials(reveal bool) (*NetBoxCredentialsSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bundle, err := m.loadSavedBundle()
	if err != nil {
		return &NetBoxCredentialsSummary{
			Configured:         false,
			SuperuserUsername:  "admin",
			SuperuserEmail:     "admin@axonwall.local",
			EndpointURL:        "https://netbox.axonwall.local",
			InternalServiceURL: "http://netbox.netbox.svc.cluster.local:8080",
		}, nil
	}
	secrets, err := m.ensureSecretsLocked("", "")
	if err != nil {
		return nil, err
	}

	preview := ""
	if len(secrets.APIToken) >= 8 {
		preview = secrets.APIToken[:4] + "…" + secrets.APIToken[len(secrets.APIToken)-4:]
	} else if secrets.APIToken != "" {
		preview = "********"
	}

	out := &NetBoxCredentialsSummary{
		Configured:         true,
		SuperuserUsername:  bundle.Config.SuperuserUsername,
		SuperuserEmail:     bundle.Config.SuperuserEmail,
		EndpointURL:        bundle.EndpointURL,
		InternalServiceURL: bundle.InternalServiceURL,
		TokenPreview:       preview,
	}
	if reveal {
		out.APIToken = secrets.APIToken
		out.SuperuserPassword = secrets.SuperuserPassword
	}
	return out, nil
}

func readActiveKeaLeases(leasesPath string) []NetBoxPlannedIpAddress {
	if leasesPath == "" {
		return nil
	}
	f, err := os.Open(leasesPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil || len(records) < 2 {
		return nil
	}
	header := records[0]
	colIdx := map[string]int{}
	for i, h := range header {
		colIdx[strings.TrimSpace(h)] = i
	}
	addrCol, hasAddr := colIdx["address"]
	stateCol := colIdx["state"]
	hostCol, hasHost := colIdx["hostname"]
	hwCol, hasHw := colIdx["hwaddr"]
	if !hasAddr {
		return nil
	}

	nowSec := time.Now().Unix()
	expireCol, hasExpire := colIdx["expire"]
	seen := map[string]bool{}
	var leases []NetBoxPlannedIpAddress
	for _, row := range records[1:] {
		if len(row) <= addrCol {
			continue
		}
		if stateCol > 0 && len(row) > stateCol && strings.TrimSpace(row[stateCol]) != "0" {
			continue
		}
		if hasExpire && len(row) > expireCol {
			if exp, err := strconv.ParseInt(strings.TrimSpace(row[expireCol]), 10, 64); err == nil && exp > 0 && exp < nowSec {
				continue
			}
		}
		ip := strings.TrimSpace(row[addrCol])
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		host := ""
		if hasHost && len(row) > hostCol {
			host = strings.TrimSpace(row[hostCol])
		}
		mac := ""
		if hasHw && len(row) > hwCol {
			mac = strings.TrimSpace(row[hwCol])
		}
		desc := "Active Kea DHCPv4 lease"
		if mac != "" {
			desc += " (" + mac + ")"
		}
		leases = append(leases, NetBoxPlannedIpAddress{
			Address:     ip + "/32",
			Status:      "dhcp",
			DNSName:     host,
			Description: desc,
		})
	}
	return leases
}

var nonSlugRe = regexp.MustCompile(`[^a-z0-9-]+`)

func toNetBoxSlug(s string) string {
	lower := strings.ToLower(strings.TrimSpace(s))
	slug := nonSlugRe.ReplaceAllString(lower, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "axonwall"
	}
	return slug
}

type netBoxAPIClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func (c *netBoxAPIClient) doJSON(ctx context.Context, method, path string, payload any) (int, map[string]any, error) {
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
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Token "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var decoded map[string]any
	if len(respBytes) > 0 {
		_ = json.Unmarshal(respBytes, &decoded)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, decoded, fmt.Errorf("%s %s returned HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	return resp.StatusCode, decoded, nil
}

func (c *netBoxAPIClient) lookupID(ctx context.Context, endpointPath, queryKey, queryVal string) (int, error) {
	q := url.Values{}
	q.Set(queryKey, queryVal)
	q.Set("limit", "1")
	_, data, err := c.doJSON(ctx, http.MethodGet, endpointPath+"?"+q.Encode(), nil)
	if err != nil {
		return 0, err
	}
	results, _ := data["results"].([]any)
	if len(results) == 0 {
		return 0, nil
	}
	first, _ := results[0].(map[string]any)
	if idFloat, ok := first["id"].(float64); ok {
		return int(idFloat), nil
	}
	return 0, nil
}

func (c *netBoxAPIClient) ensureObject(ctx context.Context, endpointPath, lookupKey, lookupVal string, payload map[string]any, counts *NetBoxSyncCounts) (int, error) {
	id, err := c.lookupID(ctx, endpointPath, lookupKey, lookupVal)
	if err != nil {
		return 0, err
	}
	if id > 0 {
		if _, _, err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("%s%d/", endpointPath, id), payload); err != nil {
			return id, err
		}
		if counts != nil {
			counts.Updated++
		}
		return id, nil
	}
	_, created, err := c.doJSON(ctx, http.MethodPost, endpointPath, payload)
	if err != nil {
		return 0, err
	}
	if counts != nil {
		counts.Created++
	}
	if idFloat, ok := created["id"].(float64); ok {
		return int(idFloat), nil
	}
	return 0, nil
}

func (m *NetBoxManager) SyncInventory(ctx context.Context, req *NetBoxSyncRequest) (*NetBoxSyncResult, error) {
	if req == nil {
		req = &NetBoxSyncRequest{}
	}

	m.mu.Lock()
	bundle, err := m.loadSavedBundle()
	secrets, secErr := m.ensureSecretsLocked("", "")
	m.mu.Unlock()
	if err != nil || bundle == nil {
		return nil, fmt.Errorf("NetBox plugin has not been configured on this host yet (save & apply NetBox settings first)")
	}
	if secErr != nil {
		return nil, secErr
	}

	plan := bundle.SyncPlan
	if bundle.Config.Sync.SyncDhcpLeases {
		extraLeases := readActiveKeaLeases(m.keaLeasesPath)
		existingIPs := map[string]bool{}
		for _, ip := range plan.IPAddresses {
			existingIPs[strings.Split(ip.Address, "/")[0]] = true
		}
		for _, l := range extraLeases {
			bare := strings.Split(l.Address, "/")[0]
			if !existingIPs[bare] {
				existingIPs[bare] = true
				plan.IPAddresses = append(plan.IPAddresses, l)
			}
		}
	}

	var k3sNodes []K3sNodeInfo
	if bundle.Config.Sync.SyncK3sNodes && m.k3sManager != nil {
		k3sSt := m.k3sManager.GetStatus()
		k3sNodes = k3sSt.Nodes
	}

	var liveVMs []VMStatus
	var liveCTs []ContainerStatus
	if bundle.Config.Sync.SyncVirtualMachines && m.virtManager != nil {
		liveVMs = m.virtManager.ListVMs()
		liveCTs = m.virtManager.ListContainers()
	}

	endpoint := strings.TrimSpace(req.EndpointOverride)
	if endpoint == "" {
		_, clusterIP := m.inspectK3sResources(ctx, bundle.Namespace)
		endpoint = m.resolveReachableBaseURL(ctx, bundle, clusterIP)
	}
	validEndpoint, err := validateNetBoxEndpointURL(endpoint)
	if err != nil {
		return nil, err
	}

	res := &NetBoxSyncResult{
		Success:   true,
		DryRun:    req.DryRun,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Endpoint:  validEndpoint,
	}

	// Merge live VMs/containers not already in static plan
	plannedVMNames := map[string]bool{}
	for _, vm := range plan.VirtualMachines {
		plannedVMNames[vm.Name] = true
	}
	for _, lvm := range liveVMs {
		if lvm.Name != "" && !plannedVMNames[lvm.Name] {
			plannedVMNames[lvm.Name] = true
			status := "offline"
			if lvm.Status == "running" {
				status = "active"
			}
			plan.VirtualMachines = append(plan.VirtualMachines, NetBoxPlannedVirtualMachine{
				Name:     lvm.Name,
				Kind:     "kvm",
				VCPUs:    lvm.Cores,
				MemoryMb: lvm.MemoryMb,
				DiskGb:   32,
				Status:   status,
				Comments: fmt.Sprintf("Live KVM VM #%d", lvm.VMID),
			})
		}
	}
	for _, lct := range liveCTs {
		if lct.Name != "" && !plannedVMNames[lct.Name] {
			plannedVMNames[lct.Name] = true
			status := "offline"
			if lct.Status == "running" {
				status = "active"
			}
			plan.VirtualMachines = append(plan.VirtualMachines, NetBoxPlannedVirtualMachine{
				Name:      lct.Name,
				Kind:      "lxc",
				VCPUs:     lct.Cores,
				MemoryMb:  lct.MemoryMb,
				DiskGb:    8,
				Status:    status,
				PrimaryIP: lct.IPAddress,
				Comments:  fmt.Sprintf("Live LXC CT #%d", lct.CTID),
			})
		}
	}

	if req.DryRun {
		res.DevicesSynced = 1 + len(k3sNodes)
		res.VRFs.Created = len(plan.VRFs)
		res.VLANs.Created = len(plan.VLANs)
		res.Interfaces.Created = len(plan.Interfaces)
		res.Prefixes.Created = len(plan.Prefixes)
		res.IPAddresses.Created = len(plan.IPAddresses)
		res.VirtualMachines.Created = len(plan.VirtualMachines)
		return res, nil
	}

	client := &netBoxAPIClient{
		baseURL:    validEndpoint,
		token:      secrets.APIToken,
		httpClient: m.httpClient,
	}

	// 1. Site
	siteName := plan.Site.Name
	if siteName == "" {
		siteName = "Axonwall Appliance"
	}
	siteSlug := plan.Site.Slug
	if siteSlug == "" {
		siteSlug = toNetBoxSlug(siteName)
	}
	siteID, err := client.ensureObject(ctx, "/api/dcim/sites/", "slug", siteSlug, map[string]any{
		"name":   siteName,
		"slug":   siteSlug,
		"status": "active",
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing site: %v", err)
		return res, err
	}

	// 2. Manufacturer, Device Roles, Device Type
	mfgID, err := client.ensureObject(ctx, "/api/dcim/manufacturers/", "slug", "axonwall", map[string]any{
		"name": "Axonwall",
		"slug": "axonwall",
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing manufacturer: %v", err)
		return res, err
	}
	fwRoleID, err := client.ensureObject(ctx, "/api/dcim/device-roles/", "slug", "firewall-router", map[string]any{
		"name":    "Firewall / Router",
		"slug":    "firewall-router",
		"color":   "10b981",
		"vm_role": false,
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing firewall device role: %v", err)
		return res, err
	}
	k3sRoleID, _ := client.ensureObject(ctx, "/api/dcim/device-roles/", "slug", "k3s-node", map[string]any{
		"name":    "K3s Node",
		"slug":    "k3s-node",
		"color":   "0ea5e9",
		"vm_role": false,
	}, nil)
	devTypeID, err := client.ensureObject(ctx, "/api/dcim/device-types/", "slug", "axonwall-appliance", map[string]any{
		"manufacturer": mfgID,
		"model":        "Axonwall Appliance",
		"slug":         "axonwall-appliance",
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing device type: %v", err)
		return res, err
	}

	// 3. Devices (primary appliance + K3s nodes)
	deviceName := plan.Device.Hostname
	if deviceName == "" {
		deviceName = "axonwall-fw"
	}
	primaryDevID, err := client.ensureObject(ctx, "/api/dcim/devices/", "name", deviceName, map[string]any{
		"name":        deviceName,
		"device_type": devTypeID,
		"role":        fwRoleID,
		"site":        siteID,
		"status":      "active",
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing appliance device %s: %v", deviceName, err)
		return res, err
	}
	res.DevicesSynced++

	for _, node := range k3sNodes {
		if node.Name == "" || node.Name == deviceName {
			continue
		}
		roleID := fwRoleID
		if k3sRoleID > 0 {
			roleID = k3sRoleID
		}
		devStatus := "active"
		if !strings.EqualFold(node.Status, "Ready") {
			devStatus = "offline"
		}
		if _, nErr := client.ensureObject(ctx, "/api/dcim/devices/", "name", node.Name, map[string]any{
			"name":        node.Name,
			"device_type": devTypeID,
			"role":        roleID,
			"site":        siteID,
			"status":      devStatus,
			"comments":    fmt.Sprintf("K3s Node (%s • %s • %s)", node.Roles, node.Version, node.InternalIp),
		}, nil); nErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("K3s node %s: %v", node.Name, nErr))
		} else {
			res.DevicesSynced++
		}
	}

	// 4. VRFs & VLANs
	vrfIDs := map[string]int{}
	for _, vrf := range plan.VRFs {
		payload := map[string]any{
			"name":           vrf.Name,
			"enforce_unique": vrf.EnforceUnique,
			"description":    vrf.Description,
		}
		if vrf.RD != "" {
			payload["rd"] = vrf.RD
		}
		id, vErr := client.ensureObject(ctx, "/api/ipam/vrfs/", "name", vrf.Name, payload, &res.VRFs)
		if vErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("VRF %s: %v", vrf.Name, vErr))
		} else if id > 0 {
			vrfIDs[vrf.Name] = id
		}
	}

	for _, vlan := range plan.VLANs {
		q := url.Values{}
		q.Set("vid", strconv.Itoa(vlan.VID))
		q.Set("site_id", strconv.Itoa(siteID))
		q.Set("limit", "1")
		_, existingData, listErr := client.doJSON(ctx, http.MethodGet, "/api/ipam/vlans/?"+q.Encode(), nil)
		payload := map[string]any{
			"vid":         vlan.VID,
			"name":        vlan.Name,
			"site":        siteID,
			"status":      "active",
			"description": vlan.Description,
		}
		if listErr == nil {
			if results, _ := existingData["results"].([]any); len(results) > 0 {
				first, _ := results[0].(map[string]any)
				if idF, ok := first["id"].(float64); ok && idF > 0 {
					if _, _, pErr := client.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/api/ipam/vlans/%d/", int(idF)), payload); pErr != nil {
						res.Warnings = append(res.Warnings, fmt.Sprintf("VLAN %d: %v", vlan.VID, pErr))
					} else {
						res.VLANs.Updated++
					}
					continue
				}
			}
		}
		if _, _, pErr := client.doJSON(ctx, http.MethodPost, "/api/ipam/vlans/", payload); pErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("VLAN %d: %v", vlan.VID, pErr))
		} else {
			res.VLANs.Created++
		}
	}

	// 5. Device Interfaces
	ifaceIDs := map[string]int{}
	for _, iface := range plan.Interfaces {
		if iface.Name == "" || primaryDevID == 0 {
			continue
		}
		q := url.Values{}
		q.Set("device_id", strconv.Itoa(primaryDevID))
		q.Set("name", iface.Name)
		q.Set("limit", "1")
		nbType := "other"
		switch iface.Type {
		case "virtual", "bridge", "lag":
			nbType = iface.Type
		}
		payload := map[string]any{
			"device":      primaryDevID,
			"name":        iface.Name,
			"type":        nbType,
			"enabled":     iface.Enabled,
			"description": iface.Description,
		}
		if iface.MTU > 0 {
			payload["mtu"] = iface.MTU
		}
		_, existingData, listErr := client.doJSON(ctx, http.MethodGet, "/api/dcim/interfaces/?"+q.Encode(), nil)
		if listErr == nil {
			if results, _ := existingData["results"].([]any); len(results) > 0 {
				first, _ := results[0].(map[string]any)
				if idF, ok := first["id"].(float64); ok && idF > 0 {
					id := int(idF)
					if _, _, pErr := client.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/api/dcim/interfaces/%d/", id), payload); pErr != nil {
						res.Warnings = append(res.Warnings, fmt.Sprintf("Interface %s: %v", iface.Name, pErr))
					} else {
						res.Interfaces.Updated++
						ifaceIDs[iface.Name] = id
					}
					continue
				}
			}
		}
		_, created, pErr := client.doJSON(ctx, http.MethodPost, "/api/dcim/interfaces/", payload)
		if pErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Interface %s: %v", iface.Name, pErr))
		} else {
			res.Interfaces.Created++
			if idF, ok := created["id"].(float64); ok {
				ifaceIDs[iface.Name] = int(idF)
			}
		}
	}

	// 6. Prefixes
	for _, pref := range plan.Prefixes {
		payload := map[string]any{
			"prefix":      pref.Prefix,
			"status":      "active",
			"site":        siteID,
			"description": pref.Description,
		}
		if vrfID, ok := vrfIDs[pref.VRF]; ok {
			payload["vrf"] = vrfID
		}
		if _, pErr := client.ensureObject(ctx, "/api/ipam/prefixes/", "prefix", pref.Prefix, payload, &res.Prefixes); pErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Prefix %s: %v", pref.Prefix, pErr))
		}
	}

	// 7. IP Addresses
	for _, ip := range plan.IPAddresses {
		payload := map[string]any{
			"address":     ip.Address,
			"status":      ip.Status,
			"description": ip.Description,
		}
		if ip.Role != "" {
			payload["role"] = ip.Role
		}
		if ip.DNSName != "" {
			payload["dns_name"] = ip.DNSName
		}
		if vrfID, ok := vrfIDs[ip.VRF]; ok {
			payload["vrf"] = vrfID
		}
		if ifID, ok := ifaceIDs[ip.InterfaceName]; ok {
			payload["assigned_object_type"] = "dcim.interface"
			payload["assigned_object_id"] = ifID
		}
		if _, pErr := client.ensureObject(ctx, "/api/ipam/ip-addresses/", "address", ip.Address, payload, &res.IPAddresses); pErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("IP %s: %v", ip.Address, pErr))
		}
	}

	// 8. Virtualization Cluster & VMs/LXCs
	if len(plan.VirtualMachines) > 0 {
		ctID, ctErr := client.ensureObject(ctx, "/api/virtualization/cluster-types/", "slug", "axonwall-hypervisor", map[string]any{
			"name": "Axonwall Hypervisor",
			"slug": "axonwall-hypervisor",
		}, nil)
		if ctErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("ClusterType: %v", ctErr))
		} else {
			clID, clErr := client.ensureObject(ctx, "/api/virtualization/clusters/", "name", deviceName, map[string]any{
				"name": deviceName,
				"type": ctID,
				"site": siteID,
			}, nil)
			if clErr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("Cluster %s: %v", deviceName, clErr))
			} else {
				for _, vm := range plan.VirtualMachines {
					payload := map[string]any{
						"name":     vm.Name,
						"cluster":  clID,
						"site":     siteID,
						"status":   vm.Status,
						"vcpus":    vm.VCPUs,
						"memory":   vm.MemoryMb,
						"disk":     vm.DiskGb,
						"comments": vm.Comments,
					}
					if _, vmErr := client.ensureObject(ctx, "/api/virtualization/virtual-machines/", "name", vm.Name, payload, &res.VirtualMachines); vmErr != nil {
						res.Warnings = append(res.Warnings, fmt.Sprintf("VM %s: %v", vm.Name, vmErr))
					}
				}
			}
		}
	}

	m.mu.Lock()
	if encoded, encErr := json.MarshalIndent(res, "", "  "); encErr == nil {
		_ = writeFilesAtomic([]atomicFileWrite{
			{path: filepath.Join(m.configDir, "last-sync.json"), content: string(encoded) + "\n", perm: 0640},
		})
	}
	m.mu.Unlock()

	return res, nil
}

func nestedMapName(obj map[string]any, key string) string {
	sub, ok := obj[key].(map[string]any)
	if !ok {
		return ""
	}
	if name, ok := sub["name"].(string); ok {
		return name
	}
	if val, ok := sub["value"].(string); ok {
		return val
	}
	if disp, ok := sub["display"].(string); ok {
		return disp
	}
	return ""
}

func (c *netBoxAPIClient) listAllResults(ctx context.Context, basePath string) ([]map[string]any, error) {
	var all []map[string]any
	sep := "?"
	if strings.Contains(basePath, "?") {
		sep = "&"
	}
	nextPath := basePath + sep + "limit=200&offset=0"
	for page := 0; page < 10 && nextPath != ""; page++ {
		_, data, err := c.doJSON(ctx, http.MethodGet, nextPath, nil)
		if err != nil {
			return all, err
		}
		results, _ := data["results"].([]any)
		for _, item := range results {
			if m, ok := item.(map[string]any); ok {
				all = append(all, m)
			}
		}
		rawNext, _ := data["next"].(string)
		if strings.TrimSpace(rawNext) == "" {
			break
		}
		u, parseErr := url.Parse(rawNext)
		if parseErr != nil {
			break
		}
		nextPath = u.Path
		if u.RawQuery != "" {
			nextPath += "?" + u.RawQuery
		}
	}
	return all, nil
}

func extractNetBoxCableTermination(raw any) (devName, ifaceName string, ifaceID int) {
	list, _ := raw.([]any)
	if len(list) == 0 {
		return "", "", 0
	}
	first, _ := list[0].(map[string]any)
	if idF, ok := first["object_id"].(float64); ok {
		ifaceID = int(idF)
	}
	obj, _ := first["object"].(map[string]any)
	if obj != nil {
		ifaceName, _ = obj["name"].(string)
		if ifaceID == 0 {
			if idF, ok := obj["id"].(float64); ok {
				ifaceID = int(idF)
			}
		}
		devName = nestedMapName(obj, "device")
	}
	return devName, ifaceName, ifaceID
}

func canonicalCableKey(aDev, aIface, bDev, bIface string) string {
	left := strings.ToLower(strings.TrimSpace(aDev)) + ":" + strings.ToLower(strings.TrimSpace(aIface))
	right := strings.ToLower(strings.TrimSpace(bDev)) + ":" + strings.ToLower(strings.TrimSpace(bIface))
	if left <= right {
		return left + "<->" + right
	}
	return right + "<->" + left
}

func (m *NetBoxManager) resolveClient(ctx context.Context, endpointOverride string) (*netBoxAPIClient, *NetBoxRuntimeBundle, error) {
	m.mu.Lock()
	bundle, err := m.loadSavedBundle()
	secrets, secErr := m.ensureSecretsLocked("", "")
	m.mu.Unlock()
	if err != nil || bundle == nil {
		return nil, nil, fmt.Errorf("NetBox plugin has not been configured on this host yet")
	}
	if secErr != nil {
		return nil, bundle, secErr
	}
	endpoint := strings.TrimSpace(endpointOverride)
	if endpoint == "" {
		_, clusterIP := m.inspectK3sResources(ctx, bundle.Namespace)
		endpoint = m.resolveReachableBaseURL(ctx, bundle, clusterIP)
	}
	validEndpoint, urlErr := validateNetBoxEndpointURL(endpoint)
	if urlErr != nil {
		return nil, bundle, urlErr
	}
	return &netBoxAPIClient{
		baseURL:    validEndpoint,
		token:      secrets.APIToken,
		httpClient: m.httpClient,
	}, bundle, nil
}

// ExportInventory exports devices, racks, interfaces, physical cables, prefixes, and VLANs from NetBox.
func (m *NetBoxManager) ExportInventory(ctx context.Context, endpointOverride ...string) *NetBoxInventorySnapshot {
	override := ""
	if len(endpointOverride) > 0 {
		override = endpointOverride[0]
	}
	out := &NetBoxInventorySnapshot{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Sites:      []string{},
		Racks:      []NetBoxExportedRack{},
		Devices:    []NetBoxExportedDevice{},
		Interfaces: []NetBoxExportedInterface{},
		Cables:     []NetBoxExportedCable{},
		Prefixes:   []string{},
		VLANs:      []int{},
	}

	client, _, err := m.resolveClient(ctx, override)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Endpoint = client.baseURL

	sites, err := client.listAllResults(ctx, "/api/dcim/sites/")
	if err != nil {
		out.Error = fmt.Sprintf("NetBox unreachable (%v)", err)
		return out
	}
	out.Available = true
	for _, s := range sites {
		if name, _ := s["name"].(string); name != "" {
			out.Sites = append(out.Sites, name)
		}
	}

	if racks, rErr := client.listAllResults(ctx, "/api/dcim/racks/"); rErr == nil {
		for _, r := range racks {
			idF, _ := r["id"].(float64)
			uF, _ := r["u_height"].(float64)
			name, _ := r["name"].(string)
			out.Racks = append(out.Racks, NetBoxExportedRack{
				ID:      int(idF),
				Name:    name,
				Site:    nestedMapName(r, "site"),
				UHeight: int(uF),
			})
		}
	}

	if devs, dErr := client.listAllResults(ctx, "/api/dcim/devices/"); dErr == nil {
		for _, d := range devs {
			idF, _ := d["id"].(float64)
			name, _ := d["name"].(string)
			comments, _ := d["comments"].(string)
			primIP := ""
			if pip, ok := d["primary_ip4"].(map[string]any); ok {
				primIP, _ = pip["address"].(string)
			} else if pip6, ok := d["primary_ip"].(map[string]any); ok {
				primIP, _ = pip6["address"].(string)
			}
			out.Devices = append(out.Devices, NetBoxExportedDevice{
				ID:         int(idF),
				Name:       name,
				Role:       nestedMapName(d, "role"),
				DeviceType: nestedMapName(d, "device_type"),
				Site:       nestedMapName(d, "site"),
				Rack:       nestedMapName(d, "rack"),
				PrimaryIP:  primIP,
				Status:     nestedMapName(d, "status"),
				Comments:   comments,
			})
		}
	}

	if ifaces, iErr := client.listAllResults(ctx, "/api/dcim/interfaces/"); iErr == nil {
		for _, ifc := range ifaces {
			idF, _ := ifc["id"].(float64)
			name, _ := ifc["name"].(string)
			en, _ := ifc["enabled"].(bool)
			mtuF, _ := ifc["mtu"].(float64)
			mac, _ := ifc["mac_address"].(string)
			desc, _ := ifc["description"].(string)
			var devID int
			devName := ""
			if devMap, ok := ifc["device"].(map[string]any); ok {
				if dIDF, ok := devMap["id"].(float64); ok {
					devID = int(dIDF)
				}
				devName, _ = devMap["name"].(string)
			}
			out.Interfaces = append(out.Interfaces, NetBoxExportedInterface{
				ID:          int(idF),
				DeviceID:    devID,
				DeviceName:  devName,
				Name:        name,
				Type:        nestedMapName(ifc, "type"),
				Enabled:     en,
				MTU:         int(mtuF),
				MACAddress:  mac,
				Description: desc,
			})
		}
	}

	if cables, cErr := client.listAllResults(ctx, "/api/dcim/cables/"); cErr == nil {
		for _, c := range cables {
			idF, _ := c["id"].(float64)
			aDev, aIface, _ := extractNetBoxCableTermination(c["a_terminations"])
			bDev, bIface, _ := extractNetBoxCableTermination(c["b_terminations"])
			label, _ := c["label"].(string)
			color, _ := c["color"].(string)
			lengthF, _ := c["length"].(float64)
			lenUnit := nestedMapName(c, "length_unit")
			if lenUnit == "" {
				lenUnit, _ = c["length_unit"].(string)
			}
			cType, _ := c["type"].(string)
			if cType == "" {
				cType = nestedMapName(c, "type")
			}
			comments, _ := c["comments"].(string)
			out.Cables = append(out.Cables, NetBoxExportedCable{
				ID:         int(idF),
				ADevice:    aDev,
				AInterface: aIface,
				BDevice:    bDev,
				BInterface: bIface,
				Type:       cType,
				Status:     nestedMapName(c, "status"),
				Label:      label,
				Color:      color,
				Length:     lengthF,
				LengthUnit: lenUnit,
				Comments:   comments,
			})
		}
	}

	if prefixes, pErr := client.listAllResults(ctx, "/api/ipam/prefixes/"); pErr == nil {
		for _, p := range prefixes {
			if pfx, _ := p["prefix"].(string); pfx != "" {
				out.Prefixes = append(out.Prefixes, pfx)
			}
		}
	}

	if vlans, vErr := client.listAllResults(ctx, "/api/ipam/vlans/"); vErr == nil {
		for _, v := range vlans {
			if vidF, ok := v["vid"].(float64); ok && vidF > 0 {
				out.VLANs = append(out.VLANs, int(vidF))
			}
		}
	}

	return out
}

// UpsertCablesAndDevices previews or synchronizes physical devices, interfaces, and cables into NetBox.
func (m *NetBoxManager) UpsertCablesAndDevices(ctx context.Context, req *NetBoxCablesSyncRequest) (*NetBoxCablesSyncResult, error) {
	if req == nil {
		req = &NetBoxCablesSyncRequest{}
	}
	client, bundle, err := m.resolveClient(ctx, req.EndpointOverride)
	if err != nil {
		return nil, err
	}

	res := &NetBoxCablesSyncResult{
		Success:   true,
		DryRun:    req.DryRun,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Endpoint:  client.baseURL,
		Conflicts: []NetBoxCableConflict{},
	}

	// Inspect current NetBox state to detect cable & label conflicts before mutating
	snapshot := m.ExportInventory(ctx, client.baseURL)
	existingDevIDs := map[string]int{}
	for _, d := range snapshot.Devices {
		if d.Name != "" {
			existingDevIDs[strings.ToLower(d.Name)] = d.ID
		}
	}
	existingIfaceIDs := map[string]int{}
	for _, ifc := range snapshot.Interfaces {
		if ifc.DeviceName != "" && ifc.Name != "" {
			existingIfaceIDs[strings.ToLower(ifc.DeviceName)+":"+strings.ToLower(ifc.Name)] = ifc.ID
		}
	}
	existingCables := map[string]NetBoxExportedCable{}
	for _, c := range snapshot.Cables {
		key := canonicalCableKey(c.ADevice, c.AInterface, c.BDevice, c.BInterface)
		existingCables[key] = c
	}

	if req.DryRun {
		seenDev := map[string]bool{}
		for _, d := range req.Devices {
			k := strings.ToLower(strings.TrimSpace(d.Name))
			if k == "" || seenDev[k] {
				continue
			}
			seenDev[k] = true
			if _, ok := existingDevIDs[k]; ok {
				res.Devices.Updated++
			} else {
				res.Devices.Created++
			}
		}
		for _, c := range req.Cables {
			if strings.TrimSpace(c.ADevice) == "" || strings.TrimSpace(c.AInterface) == "" ||
				strings.TrimSpace(c.BDevice) == "" || strings.TrimSpace(c.BInterface) == "" {
				continue
			}
			for _, pair := range [][2]string{{c.ADevice, c.AInterface}, {c.BDevice, c.BInterface}} {
				ifKey := strings.ToLower(strings.TrimSpace(pair[0])) + ":" + strings.ToLower(strings.TrimSpace(pair[1]))
				if _, ok := existingIfaceIDs[ifKey]; ok {
					res.Interfaces.Unchanged++
				} else {
					res.Interfaces.Created++
					existingIfaceIDs[ifKey] = -1
				}
			}
			cKey := canonicalCableKey(c.ADevice, c.AInterface, c.BDevice, c.BInterface)
			if ex, ok := existingCables[cKey]; ok {
				if c.Label != "" && ex.Label != "" && !strings.EqualFold(c.Label, ex.Label) {
					res.Conflicts = append(res.Conflicts, NetBoxCableConflict{
						Key:         cKey,
						Field:       "label",
						AxonwallVal: c.Label,
						NetBoxVal:   ex.Label,
						Resolution:  map[bool]string{true: "use-axonwall", false: "keep-netbox"}[req.OverwriteLabels],
					})
				}
				if c.Type != "" && ex.Type != "" && !strings.EqualFold(c.Type, ex.Type) {
					res.Conflicts = append(res.Conflicts, NetBoxCableConflict{
						Key:         cKey,
						Field:       "type",
						AxonwallVal: c.Type,
						NetBoxVal:   ex.Type,
						Resolution:  map[bool]string{true: "use-axonwall", false: "keep-netbox"}[req.OverwriteLabels],
					})
				}
				if req.OverwriteLabels {
					res.Cables.Updated++
				} else {
					res.Cables.Unchanged++
				}
			} else {
				res.Cables.Created++
			}
		}
		return res, nil
	}

	siteName := bundle.SyncPlan.Site.Name
	if siteName == "" {
		siteName = "Axonwall Appliance"
	}
	siteSlug := bundle.SyncPlan.Site.Slug
	if siteSlug == "" {
		siteSlug = toNetBoxSlug(siteName)
	}
	siteID, err := client.ensureObject(ctx, "/api/dcim/sites/", "slug", siteSlug, map[string]any{
		"name":   siteName,
		"slug":   siteSlug,
		"status": "active",
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing site: %v", err)
		return res, err
	}

	defaultMfgID, err := client.ensureObject(ctx, "/api/dcim/manufacturers/", "slug", "axonwall-discovered", map[string]any{
		"name": "Axonwall Discovered",
		"slug": "axonwall-discovered",
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing manufacturer: %v", err)
		return res, err
	}
	defaultRoleID, err := client.ensureObject(ctx, "/api/dcim/device-roles/", "slug", "network-device", map[string]any{
		"name":    "Network Device",
		"slug":    "network-device",
		"color":   "38bdf8",
		"vm_role": false,
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing device role: %v", err)
		return res, err
	}
	defaultTypeID, err := client.ensureObject(ctx, "/api/dcim/device-types/", "slug", "discovered-network-hardware", map[string]any{
		"manufacturer": defaultMfgID,
		"model":        "Discovered Network Hardware",
		"slug":         "discovered-network-hardware",
	}, nil)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("failed syncing device type: %v", err)
		return res, err
	}

	ensureDeviceByName := func(spec NetBoxUpsertDeviceSpec) (int, error) {
		name := strings.TrimSpace(spec.Name)
		if name == "" {
			return 0, fmt.Errorf("empty device name")
		}
		key := strings.ToLower(name)
		roleID := defaultRoleID
		if spec.Role != "" {
			rSlug := toNetBoxSlug(spec.Role)
			if rID, rErr := client.ensureObject(ctx, "/api/dcim/device-roles/", "slug", rSlug, map[string]any{
				"name":    spec.Role,
				"slug":    rSlug,
				"color":   "0ea5e9",
				"vm_role": false,
			}, nil); rErr == nil && rID > 0 {
				roleID = rID
			}
		}
		typeID := defaultTypeID
		if spec.Model != "" {
			mfgID := defaultMfgID
			if spec.Mfg != "" {
				mSlug := toNetBoxSlug(spec.Mfg)
				if mID, mErr := client.ensureObject(ctx, "/api/dcim/manufacturers/", "slug", mSlug, map[string]any{
					"name": spec.Mfg,
					"slug": mSlug,
				}, nil); mErr == nil && mID > 0 {
					mfgID = mID
				}
			}
			tSlug := toNetBoxSlug(spec.Model)
			if tID, tErr := client.ensureObject(ctx, "/api/dcim/device-types/", "slug", tSlug, map[string]any{
				"manufacturer": mfgID,
				"model":        spec.Model,
				"slug":         tSlug,
			}, nil); tErr == nil && tID > 0 {
				typeID = tID
			}
		}
		status := spec.Status
		if status == "" {
			status = "active"
		}
		payload := map[string]any{
			"name":        name,
			"device_type": typeID,
			"role":        roleID,
			"site":        siteID,
			"status":      status,
		}
		if spec.Comments != "" {
			payload["comments"] = spec.Comments
		}
		id, dErr := client.ensureObject(ctx, "/api/dcim/devices/", "name", name, payload, &res.Devices)
		if dErr == nil && id > 0 {
			existingDevIDs[key] = id
		}
		return id, dErr
	}

	for _, d := range req.Devices {
		if _, dErr := ensureDeviceByName(d); dErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Device %s: %v", d.Name, dErr))
		}
	}

	ensureDeviceInterface := func(devName, ifName string) (int, error) {
		devKey := strings.ToLower(strings.TrimSpace(devName))
		ifKey := devKey + ":" + strings.ToLower(strings.TrimSpace(ifName))
		if id, ok := existingIfaceIDs[ifKey]; ok && id > 0 {
			res.Interfaces.Unchanged++
			return id, nil
		}
		devID := existingDevIDs[devKey]
		if devID == 0 {
			var dErr error
			devID, dErr = ensureDeviceByName(NetBoxUpsertDeviceSpec{Name: devName, Status: "active"})
			if dErr != nil || devID == 0 {
				return 0, fmt.Errorf("device %s not found: %v", devName, dErr)
			}
		}
		q := url.Values{}
		q.Set("device_id", strconv.Itoa(devID))
		q.Set("name", ifName)
		q.Set("limit", "1")
		if _, existingData, lErr := client.doJSON(ctx, http.MethodGet, "/api/dcim/interfaces/?"+q.Encode(), nil); lErr == nil {
			if results, _ := existingData["results"].([]any); len(results) > 0 {
				first, _ := results[0].(map[string]any)
				if idF, ok := first["id"].(float64); ok && idF > 0 {
					id := int(idF)
					existingIfaceIDs[ifKey] = id
					res.Interfaces.Unchanged++
					return id, nil
				}
			}
		}
		_, created, pErr := client.doJSON(ctx, http.MethodPost, "/api/dcim/interfaces/", map[string]any{
			"device":  devID,
			"name":    ifName,
			"type":    "1000base-t",
			"enabled": true,
		})
		if pErr != nil {
			return 0, pErr
		}
		res.Interfaces.Created++
		if idF, ok := created["id"].(float64); ok && idF > 0 {
			id := int(idF)
			existingIfaceIDs[ifKey] = id
			return id, nil
		}
		return 0, fmt.Errorf("NetBox did not return interface id for %s:%s", devName, ifName)
	}

	for _, c := range req.Cables {
		if strings.TrimSpace(c.ADevice) == "" || strings.TrimSpace(c.AInterface) == "" ||
			strings.TrimSpace(c.BDevice) == "" || strings.TrimSpace(c.BInterface) == "" {
			continue
		}
		aID, aErr := ensureDeviceInterface(c.ADevice, c.AInterface)
		if aErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Cable %s:%s -> %s:%s endpoint A: %v", c.ADevice, c.AInterface, c.BDevice, c.BInterface, aErr))
			continue
		}
		bID, bErr := ensureDeviceInterface(c.BDevice, c.BInterface)
		if bErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Cable %s:%s -> %s:%s endpoint B: %v", c.ADevice, c.AInterface, c.BDevice, c.BInterface, bErr))
			continue
		}
		if aID == bID {
			continue
		}

		cKey := canonicalCableKey(c.ADevice, c.AInterface, c.BDevice, c.BInterface)
		status := c.Status
		if status == "" {
			status = "connected"
		}
		payload := map[string]any{
			"a_terminations": []map[string]any{{"object_type": "dcim.interface", "object_id": aID}},
			"b_terminations": []map[string]any{{"object_type": "dcim.interface", "object_id": bID}},
			"status":         status,
		}
		if c.Type != "" {
			payload["type"] = c.Type
		}
		if c.Label != "" {
			payload["label"] = c.Label
		}
		if cleanColor := strings.TrimPrefix(strings.TrimSpace(c.Color), "#"); cleanColor != "" {
			payload["color"] = cleanColor
		}
		if c.Length > 0 {
			payload["length"] = c.Length
			unit := c.LengthUnit
			if unit == "" {
				unit = "m"
			}
			payload["length_unit"] = unit
		}
		if c.Comments != "" {
			payload["comments"] = c.Comments
		}

		if ex, ok := existingCables[cKey]; ok && ex.ID > 0 {
			if c.Label != "" && ex.Label != "" && !strings.EqualFold(c.Label, ex.Label) {
				res.Conflicts = append(res.Conflicts, NetBoxCableConflict{
					Key:         cKey,
					Field:       "label",
					AxonwallVal: c.Label,
					NetBoxVal:   ex.Label,
					Resolution:  map[bool]string{true: "use-axonwall", false: "keep-netbox"}[req.OverwriteLabels],
				})
				if !req.OverwriteLabels {
					payload["label"] = ex.Label
				}
			}
			if _, _, pErr := client.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/api/dcim/cables/%d/", ex.ID), payload); pErr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("Cable %s: %v", cKey, pErr))
			} else {
				res.Cables.Updated++
			}
			continue
		}

		if _, _, pErr := client.doJSON(ctx, http.MethodPost, "/api/dcim/cables/", payload); pErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Cable %s: %v", cKey, pErr))
		} else {
			res.Cables.Created++
		}
	}

	return res, nil
}
