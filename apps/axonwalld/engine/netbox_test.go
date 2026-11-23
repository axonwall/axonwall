package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func sampleNetBoxManifestYAML() string {
	return `apiVersion: v1
kind: Namespace
metadata:
  name: "netbox"
---
apiVersion: v1
kind: Secret
metadata:
  name: netbox-secrets
  namespace: "netbox"
type: Opaque
stringData:
  db_password: "__AXONWALL_NETBOX_DB_PASSWORD__"
  redis_password: "__AXONWALL_NETBOX_REDIS_PASSWORD__"
  secret_key: "__AXONWALL_NETBOX_SECRET_KEY__"
  superuser_password: "__AXONWALL_NETBOX_SUPERUSER_PASSWORD__"
  superuser_api_token: "__AXONWALL_NETBOX_API_TOKEN__"
  ldap_bind_password: "__AXONWALL_NETBOX_LDAP_BIND_PASSWORD__"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbox
  namespace: "netbox"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: netbox
  template:
    metadata:
      labels:
        app: netbox
    spec:
      containers:
        - name: netbox
          image: "netboxcommunity/netbox:v4.2"
          ports:
            - containerPort: 8080
`
}

func TestNetBoxManager_ApplyConfigSecretsAndValidation(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgDir := filepath.Join(tmpRoot, "etc-netbox")
	manifestDir := filepath.Join(tmpRoot, "manifests")
	ldapPath := filepath.Join(tmpRoot, "ldap-netbox.json")

	ldapBinding, _ := json.Marshal(PluginLDAPBinding{
		PluginID:     "netbox",
		Enabled:      true,
		BindPassword: `ldap"pass\123`,
	})
	if err := os.WriteFile(ldapPath, ldapBinding, 0600); err != nil {
		t.Fatalf("failed to write temp ldap binding: %v", err)
	}

	nm := NewNetBoxManager(cfgDir, nil, nil)
	nm.manifestDir = manifestDir
	nm.ldapBindingPath = ldapPath

	bundle := NetBoxRuntimeBundle{
		Enabled:          true,
		K3sDependencyMet: true,
		Namespace:        "netbox",
		Domain:           "netbox.axonwall.local",
		EndpointURL:      "https://netbox.axonwall.local",
		Config: NetBoxConfigMetadata{
			Namespace:         "netbox",
			Domain:            "netbox.axonwall.local",
			ServicePort:       8080,
			SuperuserUsername: "admin",
			SuperuserEmail:    "admin@axonwall.local",
			SiteName:          "HQ",
			SiteSlug:          "hq",
			Sync: NetBoxSyncFlags{
				Enabled: true,
			},
		},
		K3sManifestsYaml: sampleNetBoxManifestYAML(),
	}
	raw, _ := json.Marshal(bundle)
	if err := nm.ApplyConfig(raw); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(manifestDir, "axonwall-netbox.yaml"))
	if err != nil {
		t.Fatalf("expected axonwall-netbox.yaml written: %v", err)
	}
	manifestStr := string(manifestBytes)
	if strings.Contains(manifestStr, "__AXONWALL_NETBOX_") {
		t.Fatalf("unsubstituted placeholder found in rendered manifest")
	}
	if !strings.Contains(manifestStr, `"ldap\"pass\\123"`) {
		t.Fatalf("expected properly escaped LDAP bind password in manifest, got:\n%s", manifestStr)
	}
	if err := validateK3sManifest(manifestStr); err != nil {
		t.Fatalf("rendered manifest failed validateK3sManifest: %v", err)
	}

	// secrets.json must be 0600 and contain generated credentials
	secInfo, err := os.Stat(filepath.Join(cfgDir, "secrets.json"))
	if err != nil {
		t.Fatalf("expected secrets.json: %v", err)
	}
	if secInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected secrets.json mode 0600, got %o", secInfo.Mode().Perm())
	}

	// Reveal=false hides secrets, Reveal=true exposes them
	hiddenCreds, err := nm.GetBootstrapCredentials(false)
	if err != nil || !hiddenCreds.Configured || hiddenCreds.APIToken != "" || hiddenCreds.TokenPreview == "" {
		t.Fatalf("unexpected hidden creds: %+v err=%v", hiddenCreds, err)
	}
	revealedCreds, err := nm.GetBootstrapCredentials(true)
	if err != nil || len(revealedCreds.APIToken) < 20 || len(revealedCreds.SuperuserPassword) < 12 {
		t.Fatalf("unexpected revealed creds: %+v err=%v", revealedCreds, err)
	}

	// Unsafe manifest must fail closed
	unsafeBundle := bundle
	unsafeBundle.K3sManifestsYaml = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: evil
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: c
          image: alpine:latest
`
	unsafeRaw, _ := json.Marshal(unsafeBundle)
	if err := nm.ApplyConfig(unsafeRaw); err == nil {
		t.Fatalf("expected unsafe hostNetwork manifest to be rejected fail-closed")
	}

	// Disabling removes the K3s manifest cleanly
	disabledBundle := bundle
	disabledBundle.Enabled = false
	disRaw, _ := json.Marshal(disabledBundle)
	if err := nm.ApplyConfig(disRaw); err != nil {
		t.Fatalf("disable ApplyConfig failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(manifestDir, "axonwall-netbox.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected axonwall-netbox.yaml to be removed when disabled")
	}
}

func TestNetBoxManager_SyncInventoryDryRunAndLiveUpsert(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgDir := filepath.Join(tmpRoot, "etc-netbox")
	manifestDir := filepath.Join(tmpRoot, "manifests")
	keaCSV := filepath.Join(tmpRoot, "kea-leases4.csv")
	if err := os.WriteFile(keaCSV, []byte(
		"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n"+
			"10.80.0.123,aa:bb:cc:dd:ee:01,,3600,4102444800,1,0,0,laptop-01,0,\n",
	), 0644); err != nil {
		t.Fatalf("failed to write kea leases: %v", err)
	}

	var writeCalls atomic.Int32
	seenIDs := map[string]int{}
	nextID := 10

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token deadbeef012345678901234567890123456789ab" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			key := r.URL.Path + "?" + r.URL.RawQuery
			if id, ok := seenIDs[key]; ok {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"results": []map[string]any{{"id": id}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		writeCalls.Add(1)
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			nextID++
			// Record under possible lookup query keys for subsequent pass
			switch r.URL.Path {
			case "/api/dcim/sites/":
				if slug, _ := body["slug"].(string); slug != "" {
					seenIDs[r.URL.Path+"?limit=1&slug="+slug] = nextID
				}
			case "/api/dcim/manufacturers/", "/api/dcim/device-roles/", "/api/dcim/device-types/", "/api/virtualization/cluster-types/":
				if slug, _ := body["slug"].(string); slug != "" {
					seenIDs[r.URL.Path+"?limit=1&slug="+slug] = nextID
				}
			case "/api/dcim/devices/", "/api/ipam/vrfs/", "/api/virtualization/clusters/", "/api/virtualization/virtual-machines/":
				if name, _ := body["name"].(string); name != "" {
					seenIDs[r.URL.Path+"?limit=1&name="+name] = nextID
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": nextID})
			return
		}
		if r.Method == http.MethodPatch {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		}
	}))
	defer srv.Close()

	nm := NewNetBoxManager(cfgDir, nil, nil)
	nm.manifestDir = manifestDir
	nm.keaLeasesPath = keaCSV
	nm.httpClient = srv.Client()

	bundle := NetBoxRuntimeBundle{
		Enabled:          true,
		K3sDependencyMet: true,
		Namespace:        "netbox",
		Domain:           "netbox.axonwall.local",
		EndpointURL:      srv.URL,
		APIToken:         "deadbeef012345678901234567890123456789ab",
		Config: NetBoxConfigMetadata{
			Namespace:         "netbox",
			Domain:            "netbox.axonwall.local",
			ServicePort:       8080,
			SuperuserUsername: "admin",
			SuperuserEmail:    "admin@axonwall.local",
			SiteName:          "HQ",
			SiteSlug:          "hq",
			Sync: NetBoxSyncFlags{
				Enabled:             true,
				SyncInterfaces:      true,
				SyncVlans:           true,
				SyncVrfs:            true,
				SyncPrefixes:        true,
				SyncDhcpLeases:      true,
				SyncVirtualIps:      true,
				SyncVirtualMachines: true,
				SyncK3sNodes:        true,
			},
		},
		K3sManifestsYaml: sampleNetBoxManifestYAML(),
		SyncPlan: NetBoxSyncPlan{
			VRFs: []NetBoxPlannedVrf{{Name: "red-vrf", RD: "65000:100"}},
			VLANs: []NetBoxPlannedVlan{{VID: 20, Name: "eth1.20", ParentInterface: "eth1"}},
			Interfaces: []NetBoxPlannedInterface{
				{Name: "eth1", Device: "fw-01", Type: "other", Enabled: true, MTU: 1500},
			},
			Prefixes: []NetBoxPlannedPrefix{
				{Prefix: "10.80.0.0/24", Family: 4, Status: "active"},
			},
			IPAddresses: []NetBoxPlannedIpAddress{
				{Address: "10.80.0.1/24", InterfaceName: "eth1", Status: "active"},
			},
			VirtualMachines: []NetBoxPlannedVirtualMachine{
				{Name: "app-vm", Kind: "kvm", VCPUs: 2, MemoryMb: 2048, DiskGb: 20, Status: "active"},
			},
		},
	}
	bundle.SyncPlan.Site.Name = "HQ"
	bundle.SyncPlan.Site.Slug = "hq"
	bundle.SyncPlan.Device.Hostname = "fw-01"

	raw, _ := json.Marshal(bundle)
	if err := nm.ApplyConfig(raw); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	// 1. Dry-run makes zero write HTTP calls
	dryRes, err := nm.SyncInventory(context.Background(), &NetBoxSyncRequest{
		DryRun:           true,
		EndpointOverride: srv.URL,
	})
	if err != nil {
		t.Fatalf("DryRun SyncInventory failed: %v", err)
	}
	if !dryRes.DryRun || writeCalls.Load() != 0 {
		t.Fatalf("expected 0 writes during dryRun, got %d", writeCalls.Load())
	}
	if dryRes.IPAddresses.Created != 2 { // 10.80.0.1/24 + Kea lease 10.80.0.123/32
		t.Fatalf("expected 2 planned IPs (1 static + 1 kea lease), got %+v", dryRes.IPAddresses)
	}

	// 2. Live sync posts objects and persists last-sync.json
	liveRes, err := nm.SyncInventory(context.Background(), &NetBoxSyncRequest{
		DryRun:           false,
		EndpointOverride: srv.URL,
	})
	if err != nil {
		t.Fatalf("Live SyncInventory failed: %v", err)
	}
	if !liveRes.Success || liveRes.DevicesSynced != 1 || liveRes.VRFs.Created != 1 || liveRes.VirtualMachines.Created != 1 {
		t.Fatalf("unexpected live sync summary: %+v", liveRes)
	}
	if len(liveRes.Warnings) > 0 {
		t.Fatalf("unexpected sync warnings: %v", liveRes.Warnings)
	}
	if writeCalls.Load() == 0 {
		t.Fatalf("expected REST writes during live sync")
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "last-sync.json")); err != nil {
		t.Fatalf("expected last-sync.json persisted: %v", err)
	}
}
