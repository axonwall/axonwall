package engine

import (
	"encoding/json"
	"testing"
)

func applyNasBundle(t *testing.T, m *NasManager, bundle NasRuntimeBundle) error {
	t.Helper()
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return m.ApplyConfig(raw)
}

// A-M16: NAS ApplyConfig must fail the apply when a pool/dataset/config
// step fails, instead of swallowing the failure and reporting success.
func TestBatch7_NasApplyConfigPropagatesFailures(t *testing.T) {
	// Invalid pool spec: rejected before anything is stored or run.
	m := NewNasManager()
	err := applyNasBundle(t, m, NasRuntimeBundle{
		Enabled: true,
		Pools:   []ZfsPoolSpec{{Name: "bad;name", Topology: "mirror", Compression: "lz4", DataDisks: []string{"/dev/sda"}}},
	})
	if err == nil {
		t.Fatal("ApplyConfig with invalid pool spec returned nil, want error")
	}

	// Invalid dataset spec: same treatment.
	m = NewNasManager()
	err = applyNasBundle(t, m, NasRuntimeBundle{
		Enabled:  true,
		Datasets: []ZfsDatasetSpec{{Name: "bad name", Pool: "tank"}},
	})
	if err == nil {
		t.Fatal("ApplyConfig with invalid dataset spec returned nil, want error")
	}

	// Valid pool spec but no zpool tooling in this environment: the
	// pool cannot be created, so the apply must fail rather than claim
	// the NAS is configured.
	m = NewNasManager()
	err = applyNasBundle(t, m, NasRuntimeBundle{
		Enabled: true,
		Pools:   []ZfsPoolSpec{{Name: "tank", Topology: "mirror", Compression: "lz4", DataDisks: []string{"/dev/sda", "/dev/sdb"}}},
	})
	if err == nil {
		t.Fatal("ApplyConfig with uncreatable pool returned nil, want error")
	}

	// Enabled bundle with nothing to provision still succeeds.
	m = NewNasManager()
	if err := applyNasBundle(t, m, NasRuntimeBundle{Enabled: true}); err != nil {
		t.Fatalf("ApplyConfig empty enabled bundle: %v", err)
	}

	// Disabled bundle succeeds without touching ZFS.
	m = NewNasManager()
	if err := applyNasBundle(t, m, NasRuntimeBundle{Enabled: false}); err != nil {
		t.Fatalf("ApplyConfig disabled bundle: %v", err)
	}
}

// A-M18: ListPools must never fabricate ONLINE pools with invented sizes
// when zpool has no data for a configured pool.
func TestBatch7_NasListPoolsNeverFabricates(t *testing.T) {
	m := NewNasManager()
	if err := applyNasBundle(t, m, NasRuntimeBundle{
		Enabled: true,
		Pools:   []ZfsPoolSpec{{Name: "tank", Topology: "mirror", Compression: "lz4", DataDisks: []string{"/dev/sda"}}},
	}); err == nil {
		// On a host with zpool and the pool present this succeeds;
		// the assertion below still holds (live data only).
		t.Logf("ApplyConfig succeeded (zpool present); continuing with live-data check")
	}
	pools := m.ListPools()
	for _, p := range pools {
		if p.Name == "tank" && p.Health == "ONLINE" && p.SizeBytes == 100*1024*1024*1024 {
			t.Fatalf("ListPools fabricated the 100 GiB ONLINE pool for a configured pool: %+v", p)
		}
	}
	// In this sandbox zpool is absent, so no live data exists at all.
	if got := len(pools); got != 0 {
		t.Fatalf("ListPools with no zpool data returned %d pools, want 0 (live data only)", got)
	}
}
