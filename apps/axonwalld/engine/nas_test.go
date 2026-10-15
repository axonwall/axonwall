package engine

import (
	"reflect"
	"testing"
)

func TestBuildZfsPoolCreateArgs_StripeAndMirror(t *testing.T) {
	stripePool := ZfsPoolSpec{
		Name:        "tank",
		Topology:    "stripe",
		DataDisks:   []string{"/dev/sdb", "/dev/sdc"},
		Ashift:      12,
		Autotrim:    true,
		Compression: "lz4",
	}
	gotStripe := BuildZfsPoolCreateArgs(stripePool)
	wantStripe := []string{
		"create", "-f",
		"-o", "ashift=12",
		"-o", "autotrim=on",
		"-O", "compression=lz4",
		"-O", "acltype=posixacl",
		"-O", "xattr=sa",
		"-O", "dnodesize=auto",
		"-O", "normalization=formD",
		"-O", "mountpoint=/mnt/tank",
		"tank",
		"/dev/sdb", "/dev/sdc",
	}
	if !reflect.DeepEqual(gotStripe, wantStripe) {
		t.Fatalf("stripe args mismatch:\ngot:  %v\nwant: %v", gotStripe, wantStripe)
	}

	mirrorPool := ZfsPoolSpec{
		Name:        "fastpool",
		Topology:    "mirror",
		DataDisks:   []string{"/dev/nvme0n1", "/dev/nvme1n1"},
		CacheDisks:  []string{"/dev/nvme2n1p1"},
		LogDisks:    []string{"/dev/nvme2n1p2", "/dev/nvme3n1p2"},
		SpareDisks:  []string{"/dev/sdd"},
		Ashift:      12,
		Autotrim:    true,
		Compression: "zstd",
	}
	gotMirror := BuildZfsPoolCreateArgs(mirrorPool)
	wantMirror := []string{
		"create", "-f",
		"-o", "ashift=12",
		"-o", "autotrim=on",
		"-O", "compression=zstd",
		"-O", "acltype=posixacl",
		"-O", "xattr=sa",
		"-O", "dnodesize=auto",
		"-O", "normalization=formD",
		"-O", "mountpoint=/mnt/fastpool",
		"fastpool",
		"mirror", "/dev/nvme0n1", "/dev/nvme1n1",
		"log", "mirror", "/dev/nvme2n1p2", "/dev/nvme3n1p2",
		"cache", "/dev/nvme2n1p1",
		"spare", "/dev/sdd",
	}
	if !reflect.DeepEqual(gotMirror, wantMirror) {
		t.Fatalf("mirror args mismatch:\ngot:  %v\nwant: %v", gotMirror, wantMirror)
	}
}

func TestBuildZfsPoolCreateArgs_RaidZAndDraid(t *testing.T) {
	raidz2Pool := ZfsPoolSpec{
		Name:      "vault",
		Topology:  "raidz2",
		DataDisks: []string{"/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd"},
	}
	gotRaidz2 := BuildZfsPoolCreateArgs(raidz2Pool)
	wantRaidz2 := []string{
		"create", "-f",
		"-o", "ashift=12",
		"-o", "autotrim=off",
		"-O", "compression=lz4",
		"-O", "acltype=posixacl",
		"-O", "xattr=sa",
		"-O", "dnodesize=auto",
		"-O", "normalization=formD",
		"-O", "mountpoint=/mnt/vault",
		"vault",
		"raidz2", "/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd",
	}
	if !reflect.DeepEqual(gotRaidz2, wantRaidz2) {
		t.Fatalf("raidz2 args mismatch:\ngot:  %v\nwant: %v", gotRaidz2, wantRaidz2)
	}

	draidPool := ZfsPoolSpec{
		Name:      "bigvault",
		Topology:  "draid1",
		DataDisks: []string{"/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd"},
	}
	gotDraid := BuildZfsPoolCreateArgs(draidPool)
	if gotDraid[len(gotDraid)-5] != "draid1" {
		t.Fatalf("expected draid1 keyword, got %v", gotDraid)
	}
}

func TestBuildZfsDatasetCreateArgs(t *testing.T) {
	fsDs := ZfsDatasetSpec{
		Pool:        "tank",
		Name:        "shares/media",
		Type:        "filesystem",
		QuotaGb:     2000,
		RecordSize:  "1M",
		Compression: "zstd",
	}
	gotFs := BuildZfsDatasetCreateArgs(fsDs)
	wantFs := [][]string{
		{
			"create", "-p",
			"-o", "compression=zstd",
			"-o", "recordsize=1M",
			"-o", "dedup=off",
			"-o", "aclmode=passthrough",
			"tank/shares/media",
		},
		{
			"set", "quota=2000G", "tank/shares/media",
		},
	}
	if !reflect.DeepEqual(gotFs, wantFs) {
		t.Fatalf("filesystem dataset args mismatch:\ngot:  %v\nwant: %v", gotFs, wantFs)
	}

	zvolDs := ZfsDatasetSpec{
		Pool:        "tank",
		Name:        "iscsi/lun0",
		Type:        "zvol",
		VolSizeGb:   100,
		Compression: "lz4",
	}
	gotZvol := BuildZfsDatasetCreateArgs(zvolDs)
	wantZvol := [][]string{
		{
			"create", "-p", "-V", "100G",
			"-o", "compression=lz4",
			"-o", "volblocksize=16K",
			"tank/iscsi/lun0",
		},
	}
	if !reflect.DeepEqual(gotZvol, wantZvol) {
		t.Fatalf("zvol dataset args mismatch:\ngot:  %v\nwant: %v", gotZvol, wantZvol)
	}
}

func TestPruneSnapshotList(t *testing.T) {
	snaps := []string{
		"tank/data@auto-hourly-20260101-0100",
		"tank/data@auto-hourly-20260101-0200",
		"tank/data@auto-hourly-20260101-0300",
		"tank/data@auto-hourly-20260101-0400",
	}
	toDelete := PruneSnapshotList(snaps, 2)
	wantDelete := []string{
		"tank/data@auto-hourly-20260101-0100",
		"tank/data@auto-hourly-20260101-0200",
	}
	if !reflect.DeepEqual(toDelete, wantDelete) {
		t.Fatalf("PruneSnapshotList mismatch:\ngot:  %v\nwant: %v", toDelete, wantDelete)
	}
}
