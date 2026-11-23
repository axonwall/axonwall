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

func sampleLibreNMSManifestYAML() string {
	return `apiVersion: v1
kind: Namespace
metadata:
  name: "librenms"
---
apiVersion: v1
kind: Secret
metadata:
  name: librenms-secrets
  namespace: "librenms"
type: Opaque
stringData:
  db_password: "__AXONWALL_LIBRENMS_DB_PASSWORD__"
  db_root_password: "__AXONWALL_LIBRENMS_DB_ROOT_PASSWORD__"
  app_key: "__AXONWALL_LIBRENMS_APP_KEY__"
  admin_password: "__AXONWALL_LIBRENMS_ADMIN_PASSWORD__"
  api_token: "__AXONWALL_LIBRENMS_API_TOKEN__"
  ldap_bind_password: "__AXONWALL_LIBRENMS_LDAP_BIND_PASSWORD__"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: librenms
  namespace: "librenms"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: librenms
  template:
    metadata:
      labels:
        app: librenms
    spec:
      containers:
        - name: librenms
          image: "librenms/librenms:25.10.0"
          ports:
            - containerPort: 8000
`
}

func TestLibreNMSManager_ApplyConfigValidationAndExternalMode(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgDir := filepath.Join(tmpRoot, "etc-librenms")
	manifestDir := filepath.Join(tmpRoot, "manifests")
	ldapPath := filepath.Join(tmpRoot, "ldap-librenms.json")

	ldapBinding, _ := json.Marshal(PluginLDAPBinding{
		PluginID:     "librenms",
		Enabled:      true,
		BindPassword: "ldap-secret-value",
	})
	if err := os.WriteFile(ldapPath, ldapBinding, 0600); err != nil {
		t.Fatalf("failed to write temp ldap binding: %v", err)
	}

	lm := NewLibreNMSManager(cfgDir, nil, nil)
	lm.manifestDir = manifestDir
	lm.ldapBindingPath = ldapPath

	bundle := LibreNMSRuntimeBundle{
		Enabled:          true,
		K3sDependencyMet: true,
		Mode:             "k3s",
		Namespace:        "librenms",
		Domain:           "librenms.axonwall.local",
		EndpointURL:      "https://librenms.axonwall.local",
		Config: LibreNMSConfigMetadata{
			Enabled:       true,
			Mode:          "k3s",
			Namespace:     "librenms",
			Domain:        "librenms.axonwall.local",
			ServicePort:   8000,
			AdminUsername: "admin",
			AdminEmail:    "admin@axonwall.local",
			SnmpDefaults: LibreNMSSnmpDefaults{
				Version:   "v2c",
				Community: "axonwall-ro",
				Port:      161,
			},
			Sync: LibreNMSSyncConfig{
				Enabled: true,
			},
		},
		K3sManifestsYaml: sampleLibreNMSManifestYAML(),
	}
	raw, _ := json.Marshal(bundle)
	if err := lm.ApplyConfig(raw); err != nil {
		t.Fatalf("ApplyConfig(k3s) failed: %v", err)
	}

	renderedBytes, err := os.ReadFile(filepath.Join(manifestDir, "axonwall-librenms.yaml"))
	if err != nil {
		t.Fatalf("expected rendered manifest to exist: %v", err)
	}
	rendered := string(renderedBytes)
	if strings.Contains(rendered, "__AXONWALL_LIBRENMS_API_TOKEN__") {
		t.Fatalf("expected secret placeholders to be hydrated")
	}
	if !strings.Contains(rendered, "ldap-secret-value") {
		t.Fatalf("expected LDAP bind password to be hydrated into Secret")
	}

	// Switching to external mode must remove the K3s manifest
	bundle.Mode = "external"
	bundle.Config.Mode = "external"
	bundle.EndpointURL = "https://nms.external.example"
	rawExt, _ := json.Marshal(bundle)
	if err := lm.ApplyConfig(rawExt); err != nil {
		t.Fatalf("ApplyConfig(external) failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(manifestDir, "axonwall-librenms.yaml")); !os.IsNotExist(err) {
		t.Fatalf("external mode must remove K3s manifest")
	}

	// Hostile hostPath manifest must be rejected cleanly
	bundle.Mode = "k3s"
	bundle.Config.Mode = "k3s"
	bundle.K3sManifestsYaml = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      volumes:\n        - name: host\n          hostPath:\n            path: /etc\n"
	rawBad, _ := json.Marshal(bundle)
	if err := lm.ApplyConfig(rawBad); err == nil {
		t.Fatalf("expected validateK3sManifest to reject hostPath manifest")
	}
}

func TestLibreNMSManager_SnapshotSyncWebhookAndNetBoxTriadBridge(t *testing.T) {
	tmpRoot := t.TempDir()
	lnmsDir := filepath.Join(tmpRoot, "etc-librenms")
	nbDir := filepath.Join(tmpRoot, "etc-netbox")
	manifestDir := filepath.Join(tmpRoot, "manifests")

	var enrolledHosts atomic.Int32
	var createdCables atomic.Int32
	var patchedCables atomic.Int32

	lnmsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Auth-Token") == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v0/system":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"system": []map[string]any{{"local_ver": "25.10.0"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v0/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"devices": []map[string]any{
					{"device_id": 1, "hostname": "core-sw01", "sysName": "core-sw01", "ip": "10.20.0.10", "os": "eos", "hardware": "DCS-7050", "status": 1},
					{"device_id": 2, "hostname": "axonwall-edge", "sysName": "axonwall-edge", "ip": "10.20.0.1", "os": "linux", "hardware": "Axonwall", "status": 1},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v0/devices":
			enrolledHosts.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v0/ports":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ports": []map[string]any{
					{"port_id": 101, "device_id": 1, "ifName": "Ethernet1", "ifOperStatus": "up", "ifAdminStatus": "up", "ifSpeed": 10000000000, "ifInOctets_rate": 12500000, "ifOutOctets_rate": 6250000, "ifMtu": 9000},
					{"port_id": 201, "device_id": 2, "ifName": "eth1", "ifOperStatus": "up", "ifAdminStatus": "up", "ifSpeed": 10000000000, "ifMtu": 1500},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v0/resources/links":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"links": []map[string]any{
					{"id": 11, "local_device_id": 1, "local_port_id": 101, "remote_device_id": 2, "remote_port_id": 201, "remote_hostname": "axonwall-edge", "remote_port": "eth1", "protocol": "lldp", "active": 1},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v0/resources/fdb":
			_ = json.NewEncoder(w).Encode(map[string]any{"fdb": []map[string]any{{"device_id": 1, "port_id": 101, "vlan_id": 20, "mac_address": "001122334455"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v0/resources/ip/arp":
			_ = json.NewEncoder(w).Encode(map[string]any{"arp": []map[string]any{{"device_id": 2, "port_id": 201, "mac_address": "aabbccddeeff", "ipv4_address": "10.20.0.10"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v0/alerts"):
			_ = json.NewEncoder(w).Encode(map[string]any{"alerts": []map[string]any{{"id": 7, "device_id": 1, "hostname": "core-sw01", "name": "High Optical Temp", "severity": "warning", "state": 1}}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/health"):
			_ = json.NewEncoder(w).Encode(map[string]any{"graphs": []map[string]any{{"name": "temperature", "desc": "SFP1 Temp", "sensor_current": 42.5, "sensor_limit": 70.0}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer lnmsSrv.Close()

	nbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/dcim/sites/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"id": 1, "name": "HQ", "slug": "hq"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/dcim/racks/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"id": 1, "name": "Rack-A", "u_height": 42}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/dcim/devices/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{
					{"id": 10, "name": "core-sw01", "status": map[string]any{"value": "active"}, "primary_ip4": map[string]any{"address": "10.20.0.10/24"}},
					{"id": 11, "name": "axonwall-edge", "status": map[string]any{"value": "active"}},
				},
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/dcim/interfaces/"):
			if strings.Contains(r.URL.RawQuery, "name=Ethernet1") {
				_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"id": 501, "name": "Ethernet1", "device": map[string]any{"id": 10, "name": "core-sw01"}}}})
			} else if strings.Contains(r.URL.RawQuery, "name=eth1") {
				_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"id": 502, "name": "eth1", "device": map[string]any{"id": 11, "name": "axonwall-edge"}}}})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"results": []map[string]any{
						{"id": 501, "name": "Ethernet1", "enabled": true, "device": map[string]any{"id": 10, "name": "core-sw01"}},
						{"id": 502, "name": "eth1", "enabled": true, "device": map[string]any{"id": 11, "name": "axonwall-edge"}},
					},
				})
			}
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/dcim/cables/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
		case r.Method == http.MethodGet && (strings.HasPrefix(r.URL.Path, "/api/ipam/prefixes/") || strings.HasPrefix(r.URL.Path, "/api/ipam/vlans/") ||
			strings.HasPrefix(r.URL.Path, "/api/dcim/manufacturers/") || strings.HasPrefix(r.URL.Path, "/api/dcim/device-roles/") || strings.HasPrefix(r.URL.Path, "/api/dcim/device-types/")):
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"id": 1}}})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/dcim/"):
			if strings.Contains(r.URL.Path, "/cables/") {
				patchedCables.Add(1)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/dcim/"):
			if strings.Contains(r.URL.Path, "/cables/") {
				createdCables.Add(1)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 99})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 1})
		}
	}))
	defer nbSrv.Close()

	nm := NewNetBoxManager(nbDir, nil, nil)
	nm.manifestDir = manifestDir
	nbBundle, _ := json.Marshal(NetBoxRuntimeBundle{
		Enabled:          true,
		K3sDependencyMet: true,
		Namespace:        "netbox",
		EndpointURL:      nbSrv.URL,
		APIToken:         "nb-tok-1234567890abcdef",
		SyncPlan: NetBoxSyncPlan{
			Site: struct {
				Name string `json:"name"`
				Slug string `json:"slug"`
			}{Name: "HQ", Slug: "hq"},
		},
	})
	if err := nm.ApplyConfig(nbBundle); err != nil {
		t.Fatalf("netbox ApplyConfig: %v", err)
	}

	lm := NewLibreNMSManager(lnmsDir, nil, nm)
	lm.manifestDir = manifestDir
	lnmsBundle, _ := json.Marshal(LibreNMSRuntimeBundle{
		Enabled:          true,
		K3sDependencyMet: true,
		Mode:             "external",
		Namespace:        "librenms",
		Domain:           "librenms.axonwall.local",
		EndpointURL:      lnmsSrv.URL,
		APIToken:         "lnms-tok-123",
		WebhookSecret:    "hook-secret-xyz",
		Config: LibreNMSConfigMetadata{
			Enabled:     true,
			Mode:        "external",
			ServicePort: 8000,
			SnmpDefaults: LibreNMSSnmpDefaults{
				Version:   "v2c",
				Community: "public",
				Port:      161,
			},
		},
		EnrollmentPlan: LibreNMSEnrollmentPlan{
			Targets: []LibreNMSEnrollmentTarget{
				{ID: "local", Hostname: "10.20.0.1", DisplayName: "axonwall-edge", Source: "local", Port: 161},
				{ID: "sat-1", Hostname: "10.20.50.10", DisplayName: "sat-1", Source: "fleet", Port: 161},
			},
		},
	})
	if err := lm.ApplyConfig(lnmsBundle); err != nil {
		t.Fatalf("librenms ApplyConfig: %v", err)
	}

	// Test webhook secret enforcement & ring buffer
	if _, err := lm.RecordWebhookAlert("wrong-secret", []byte(`{"hostname":"core-sw01"}`)); err == nil {
		t.Fatalf("expected invalid webhook secret to fail")
	}
	wh, err := lm.RecordWebhookAlert("hook-secret-xyz", []byte(`{"hostname":"core-sw01","rule":"BGP Peer Down","severity":"critical","state":1,"port_name":"Ethernet1"}`))
	if err != nil {
		t.Fatalf("valid webhook alert failed: %v", err)
	}
	if wh.Rule != "BGP Peer Down" || len(lm.ListWebhookAlerts()) != 1 {
		t.Fatalf("unexpected webhook state: %+v", wh)
	}

	ctx := context.Background()
	snap := lm.GetTopologySnapshot(ctx, lnmsSrv.URL)
	if !snap.Available || len(snap.Devices) != 2 || len(snap.Links) != 1 || len(snap.Ports) != 2 || len(snap.Alerts) != 2 {
		t.Fatalf("unexpected LibreNMS snapshot: avail=%v devs=%d links=%d ports=%d alerts=%d err=%s",
			snap.Available, len(snap.Devices), len(snap.Links), len(snap.Ports), len(snap.Alerts), snap.Error)
	}
	if snap.Links[0].LocalDevice != "core-sw01" || snap.Links[0].LocalPort != "Ethernet1" || snap.Links[0].RemoteDevice != "axonwall-edge" {
		t.Fatalf("expected resolved link endpoint names, got: %+v", snap.Links[0])
	}

	// SyncDevices: 10.20.0.1 already exists in LibreNMS mock, 10.20.50.10 is newly enrolled
	syncRes, err := lm.SyncDevices(ctx, &LibreNMSSyncRequest{DryRun: false, EndpointOverride: lnmsSrv.URL})
	if err != nil {
		t.Fatalf("SyncDevices failed: %v", err)
	}
	if syncRes.Existing != 1 || syncRes.Enrolled != 1 || enrolledHosts.Load() != 1 {
		t.Fatalf("expected 1 existing and 1 enrolled, got: %+v (posts=%d)", syncRes, enrolledHosts.Load())
	}

	// Triad Bridge: preview + push LibreNMS LLDP cables into NetBox
	preview, err := lm.SyncWithNetBox(ctx, &LibreNMSNetBoxSyncRequest{
		Action:           "preview",
		EndpointOverride: lnmsSrv.URL,
		NetBoxOverride:   nbSrv.URL,
	})
	if err != nil {
		t.Fatalf("SyncWithNetBox(preview) failed: %v", err)
	}
	if preview.DevicesQueued != 2 || preview.CablesQueued != 1 || createdCables.Load() != 0 {
		t.Fatalf("unexpected NetBox preview: %+v", preview)
	}

	pushed, err := lm.SyncWithNetBox(ctx, &LibreNMSNetBoxSyncRequest{
		Action:           "push",
		EndpointOverride: lnmsSrv.URL,
		NetBoxOverride:   nbSrv.URL,
	})
	if err != nil {
		t.Fatalf("SyncWithNetBox(push) failed: %v", err)
	}
	if createdCables.Load() != 1 || pushed.NetBoxResult.Cables.Created != 1 {
		t.Fatalf("expected 1 created cable in NetBox, got: %+v (createdCables=%d)", pushed, createdCables.Load())
	}
}
