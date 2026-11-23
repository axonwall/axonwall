package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTopologyManager_ApplyConfigLLDPGuardAndSecrets(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "etc-topology")
	origLldpd := lldpdConfPath
	lldpdConfPath = filepath.Join(tmp, "lldpd.d", "axonwall.conf")
	t.Cleanup(func() { lldpdConfPath = origLldpd })

	var svcActions []string
	tm := NewTopologyManager(cfgDir, nil, nil, nil, nil, nil)
	tm.svcRunner = func(_ context.Context, action string) error {
		svcActions = append(svcActions, action)
		return nil
	}

	bundle := TopologyRuntimeBundle{
		Enabled: true,
		Config: TopologyConfigPayload{
			Enabled: true,
			LLDP: TopologyLldpConfigPayload{
				Enabled:    true,
				ExcludeWan: true,
				Interfaces: []string{"eth1"},
			},
			Peers: []TopologyPeerHostPayload{
				{
					ID:       "vault-1",
					Name:     "Vault Host",
					Role:     "vault",
					APIURL:   "https://10.20.0.50:2966",
					APIToken: "super-secret-peer-token",
					Enabled:  true,
				},
			},
		},
		LLDP: TopologyCompiledLldpPayload{
			Enabled:               true,
			AllowedInterfaces:     []string{"eth1"},
			ExcludedWanInterfaces: []string{"eth0"},
			ConfContent:           "configure system interface pattern !eth0,!wan*,eth1\n",
		},
	}
	raw, _ := json.Marshal(bundle)
	if err := tm.ApplyConfig(raw); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	// Sanitized config.json must NOT contain raw peer token
	savedCfgBytes, err := os.ReadFile(filepath.Join(cfgDir, "config.json"))
	if err != nil {
		t.Fatalf("expected config.json to be written: %v", err)
	}
	if strings.Contains(string(savedCfgBytes), "super-secret-peer-token") {
		t.Fatalf("config.json must not contain plaintext peer APIToken")
	}
	savedSecBytes, err := os.ReadFile(filepath.Join(cfgDir, "peers-secrets.json"))
	if err != nil || !strings.Contains(string(savedSecBytes), "super-secret-peer-token") {
		t.Fatalf("peers-secrets.json should store peer token securely: err=%v", err)
	}

	// Masked re-apply preserves stored peer token
	bundle.Config.Peers[0].APIToken = topologyMaskedPlaceholder
	rawMasked, _ := json.Marshal(bundle)
	if err := tm.ApplyConfig(rawMasked); err != nil {
		t.Fatalf("ApplyConfig with mask failed: %v", err)
	}
	_, tokMap := tm.loadBundleAndPeerTokens()
	if tokMap["vault-1"] != "super-secret-peer-token" {
		t.Fatalf("expected masked peer token preservation, got %q", tokMap["vault-1"])
	}

	lldpRaw, err := os.ReadFile(lldpdConfPath)
	if err != nil {
		t.Fatalf("expected lldpd conf to be written: %v", err)
	}
	if !strings.Contains(string(lldpRaw), "!wan*") {
		t.Fatalf("lldpd conf must enforce WAN exclusion: %s", string(lldpRaw))
	}
	if len(svcActions) == 0 || svcActions[0] != "restart" {
		t.Fatalf("expected lldpd restart on enable, got: %v", svcActions)
	}
}

func TestTopologyManager_ProbeFabricPinnedTLSAndPhasedApplyRollback(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "etc-topology")
	origLldpd := lldpdConfPath
	lldpdConfPath = filepath.Join(tmp, "lldpd.d", "axonwall.conf")
	t.Cleanup(func() { lldpdConfPath = origLldpd })

	var appliedCount atomic.Int32
	var rollbackCount atomic.Int32
	var confirmedCount atomic.Int32

	peerSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer peer-tok-42" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/topology/probe":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok",
				"data": LocalTopologyProbe{
					LocalHostID: "vault-01",
					NICs: []HostNicProbe{
						{HostID: "vault-01", Device: "eth0", AdminUp: true, CarrierUp: true, SpeedMbps: 10000, MTU: 9000},
					},
				},
			})
		case "/api/v1/apply":
			appliedCount.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case "/api/v1/rollback":
			rollbackCount.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case "/api/v1/confirm":
			confirmedCount.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer peerSrv.Close()

	// Extract exact SHA-256 fingerprint from mock TLS server certificate
	leafSum := sha256.Sum256(peerSrv.Certificate().Raw)
	certPin := hex.EncodeToString(leafSum[:])

	k3sMgr := &K3sManager{
		cfg: K3sRuntimeBundle{Enabled: true},
	}
	tm := NewTopologyManager(cfgDir, k3sMgr, nil, nil, nil, nil)
	tm.lldpRunner = func(_ context.Context) ([]byte, error) {
		return []byte(`{"lldp":{"interface":[{"eth1":{"chassis":{"core-sw01":{"name":{"value":"core-sw01"}}},"port":{"id":{"value":"Ethernet1"}}}}]}}`), nil
	}
	tm.wgRunner = func(_ context.Context) ([]byte, error) {
		return []byte("wg0\tpriv\nwg0\tpub1\t(none)\t1.2.3.4:51820\t10.99.0.2/32\t9999999999\t10\t20\n"), nil
	}
	tm.kubectlRunner = func(_ context.Context, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "get endpoints"):
			return []byte(`{"items":[{"metadata":{"name":"app-svc","namespace":"default"},"subsets":[{"addresses":[{"ip":"10.42.0.5"}]}]}]}`), nil
		case strings.Contains(joined, "get services"):
			return []byte(`{"items":[{"metadata":{"name":"app-svc","namespace":"default"},"spec":{"type":"ClusterIP","clusterIP":"10.43.0.10","ports":[{"port":80}]}}]}`), nil
		case strings.Contains(joined, "get ingressroutes.traefik.io"):
			return []byte(`{"items":[{"metadata":{"name":"app-route","namespace":"default"},"spec":{"routes":[{"match":"Host(\"app.local\")","services":[{"name":"app-svc","port":80}]}]}}]}`), nil
		default:
			return []byte(`{"items":[]}`), nil
		}
	}

	// Register peer with pinned TLS cert
	rawCfg, _ := json.Marshal(TopologyRuntimeBundle{
		Enabled: true,
		Config: TopologyConfigPayload{
			Enabled: true,
			Peers: []TopologyPeerHostPayload{
				{
					ID:            "vault-01",
					Name:          "Vault Node",
					Role:          "vault",
					APIURL:        peerSrv.URL,
					APIToken:      "peer-tok-42",
					TLSCertSha256: certPin,
					Enabled:       true,
				},
			},
		},
	})
	if err := tm.ApplyConfig(rawCfg); err != nil {
		t.Fatalf("ApplyConfig peer: %v", err)
	}

	ctx := context.Background()
	snap := tm.ProbeFabric(ctx)
	if snap.Local == nil || snap.Local.K3s == nil {
		t.Fatalf("expected local & k3s probe snapshot")
	}
	if len(snap.Local.K3s.Ingresses) != 1 || snap.Local.K3s.Ingresses[0].Kind != "IngressRoute" {
		t.Fatalf("expected Traefik IngressRoute CRD auto-discovery, got: %+v", snap.Local.K3s.Ingresses)
	}
	if len(snap.Peers) != 1 || !snap.Peers[0].Reachable || len(snap.Peers[0].NICs) != 1 {
		t.Fatalf("expected pinned TLS peer probe success, got: %+v", snap.Peers)
	}

	// Hostile peer pin mismatch must FAIL closed
	badPinCfg, _ := json.Marshal(TopologyRuntimeBundle{
		Enabled: true,
		Config: TopologyConfigPayload{
			Enabled: true,
			Peers: []TopologyPeerHostPayload{
				{
					ID:            "vault-01",
					Name:          "Vault Node",
					Role:          "vault",
					APIURL:        peerSrv.URL,
					APIToken:      "peer-tok-42",
					TLSCertSha256: strings.Repeat("00", 32),
					Enabled:       true,
				},
			},
		},
	})
	_ = tm.ApplyConfig(badPinCfg)
	badSnap := tm.ProbeFabric(ctx)
	if badSnap.Peers[0].Reachable {
		t.Fatalf("expected mismatched TLS SHA-256 pin to fail closed")
	}

	// Restore valid pin and test Phase 3 local failure -> automatic peer rollback
	_ = tm.ApplyConfig(rawCfg)
	applyRes, err := tm.ApplyFabricPlan(ctx, &TopologyApplyRequest{
		ConfirmTimeoutSeconds: 120,
		PeerEdits: []TopologyPeerEdit{
			{PeerID: "vault-01", Name: "Vault Node", State: json.RawMessage(`{"version":1}`)},
		},
		HasLocalChanges: true,
	}, func(_ context.Context, _ int) error {
		return fmt.Errorf("simulated local edge apply failure")
	})
	if err == nil || applyRes.Success || !applyRes.RolledBackAny || appliedCount.Load() != 1 || rollbackCount.Load() != 1 {
		t.Fatalf("expected peer rollback on local phase failure, got: err=%v res=%+v (applied=%d rollback=%d)",
			err, applyRes, appliedCount.Load(), rollbackCount.Load())
	}

	// Now test successful Phase 1 -> 2 -> 3 + auto-confirm
	okRes, err := tm.ApplyFabricPlan(ctx, &TopologyApplyRequest{
		ConfirmTimeoutSeconds: 120,
		PeerEdits: []TopologyPeerEdit{
			{PeerID: "vault-01", Name: "Vault Node", State: json.RawMessage(`{"version":1}`)},
		},
		HasLocalChanges: true,
	}, func(_ context.Context, _ int) error {
		return nil
	})
	if err != nil || !okRes.Success || confirmedCount.Load() != 1 {
		t.Fatalf("expected successful phased apply + confirm, got: err=%v res=%+v (confirmed=%d)", err, okRes, confirmedCount.Load())
	}
}
