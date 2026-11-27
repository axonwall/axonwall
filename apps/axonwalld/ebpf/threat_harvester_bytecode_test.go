package ebpf

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

func TestThreatHarvesterUprobeAllowlistAndTidSchema(t *testing.T) {
	for _, elfFile := range []string{
		"threatharvester_x86_bpfel.o",
		"threatharvester_arm64_bpfel.o",
	} {
		spec, err := ebpf.LoadCollectionSpec(elfFile)
		if err != nil {
			t.Fatalf("ebpf.LoadCollectionSpec(%s) failed: %v", elfFile, err)
		}
		allowMap, ok := spec.Maps[ThreatHarvesterMapHarvesterUprobeAllowlist]
		if !ok {
			t.Fatalf("%s: missing expected map %q", elfFile, ThreatHarvesterMapHarvesterUprobeAllowlist)
		}
		if allowMap.Type != ebpf.Hash || allowMap.KeySize != 16 || allowMap.ValueSize != 1 {
			t.Fatalf("%s: unexpected %s map spec: type=%v keySize=%d valueSize=%d",
				elfFile, ThreatHarvesterMapHarvesterUprobeAllowlist, allowMap.Type, allowMap.KeySize, allowMap.ValueSize)
		}
		if _, ok := spec.Programs[ThreatHarvesterProgUprobeHarvesterSslWrite]; !ok {
			t.Fatalf("%s: missing expected program %q", elfFile, ThreatHarvesterProgUprobeHarvesterSslWrite)
		}
	}

	embedded, err := LoadThreatHarvester()
	if err != nil {
		t.Fatalf("LoadThreatHarvester() failed: %v", err)
	}
	if _, ok := embedded.Maps[ThreatHarvesterMapHarvesterUprobeAllowlist]; !ok {
		t.Fatalf("embedded ThreatHarvester missing map %q", ThreatHarvesterMapHarvesterUprobeAllowlist)
	}

	evType := reflect.TypeOf(ThreatHarvesterHarvesterRingEvent{})
	if _, ok := evType.FieldByName("Tid"); !ok {
		t.Fatalf("ThreatHarvesterHarvesterRingEvent missing Tid field")
	}
}
