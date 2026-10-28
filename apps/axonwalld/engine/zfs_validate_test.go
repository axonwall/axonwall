package engine

import "testing"

func TestValidateZfsPoolSpec(t *testing.T) {
	valid := ZfsPoolSpec{
		Name: "tank", Topology: "mirror", Compression: "lz4",
		DataDisks:  []string{"/dev/sda", "/dev/sdb"},
		LogDisks:   []string{"/dev/nvme0n1"},
		SpareDisks: []string{"/dev/disk/by-id/ata-WDC_WD40-XYZ"},
	}
	if err := ValidateZfsPoolSpec(valid); err != nil {
		t.Fatalf("valid pool rejected: %v", err)
	}
	draidPool := ZfsPoolSpec{
		Name: "tank", Topology: "draid2", Compression: "zstd",
		DataDisks: []string{"/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd", "/dev/sde", "/dev/sdf"},
	}
	if err := ValidateZfsPoolSpec(draidPool); err != nil {
		t.Fatalf("valid draid2 pool rejected: %v", err)
	}
	for name, pool := range map[string]ZfsPoolSpec{
		"dash name (option injection)": {Name: "-f", DataDisks: []string{"/dev/sda"}},
		"traversal name":               {Name: "../etc", DataDisks: []string{"/dev/sda"}},
		"slash name":                   {Name: "a/b", DataDisks: []string{"/dev/sda"}},
		"bad topology":                 {Name: "tank", Topology: "-o", DataDisks: []string{"/dev/sda"}},
		"bad compression":              {Name: "tank", Compression: "lz4; rm -rf /", DataDisks: []string{"/dev/sda"}},
		"partition as disk":            {Name: "tank", DataDisks: []string{"/dev/sda1"}},
		"nvme partition":               {Name: "tank", DataDisks: []string{"/dev/nvme0n1p1"}},
		"relative device":              {Name: "tank", DataDisks: []string{"sda"}},
		"option as device":             {Name: "tank", DataDisks: []string{"-m", "/etc"}},
		"no data disks":                {Name: "tank"},
	} {
		if err := ValidateZfsPoolSpec(pool); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}

func TestValidateZfsDatasetSpec(t *testing.T) {
	valid := ZfsDatasetSpec{
		Pool: "tank", Name: "media", Compression: "lz4",
		RecordSize: "128K", Dedup: "off", AclMode: "passthrough",
	}
	if err := ValidateZfsDatasetSpec(valid); err != nil {
		t.Fatalf("valid dataset rejected: %v", err)
	}
	full := ZfsDatasetSpec{Pool: "tank", Name: "tank/media", RecordSize: "1M"}
	if err := ValidateZfsDatasetSpec(full); err != nil {
		t.Fatalf("valid fully-qualified dataset rejected: %v", err)
	}
	for name, ds := range map[string]ZfsDatasetSpec{
		"traversal":      {Pool: "tank", Name: "../etc"},
		"dash name":      {Pool: "tank", Name: "-o"},
		"bad recordsize": {Pool: "tank", Name: "x", RecordSize: "3K"},
		"bad dedup":      {Pool: "tank", Name: "x", Dedup: "sometimes"},
		"bad aclmode":    {Pool: "tank", Name: "x", AclMode: "wide-open"},
		"bad type":       {Pool: "tank", Name: "x", Type: "snapshot"},
		"bad pool":       {Pool: "-o", Name: "x"},
	} {
		if err := ValidateZfsDatasetSpec(ds); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}
