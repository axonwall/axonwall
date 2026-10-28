package engine

// Validation for ZFS pool/dataset specs (audit finding D-07). The
// builders interpolate spec fields into `zpool create -f` /
// `zfs create` argv with no checks: a pool "name" or "disk" beginning
// with '-' injects zpool options, a topology string is arbitrary
// argv, and a disk entry can name the boot disk, which -f then
// destroys. These validators bound specs to what the product creates:
//
//   - pool/dataset names: ZFS-safe components, no traversal, no
//     leading dash (option injection);
//   - devices: whole disks only (/dev/sdX, /dev/vdX, /dev/nvmeXnY or
//     /dev/disk/by-id/...), never partitions, never relative paths;
//   - topology and property values: the allowlists the compiler and
//     UI draw from.

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	zfsNameComponentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-]*$`)
	zfsWholeDiskRe     = regexp.MustCompile(`^/dev/(sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+)$`)
	zfsByIDRe          = regexp.MustCompile(`^/dev/disk/by-id/[A-Za-z0-9_.\-]+$`)
)

var zfsTopologies = map[string]bool{
	"": true, "stripe": true, "mirror": true,
	"raidz": true, "raidz1": true, "raidz2": true, "raidz3": true,
	"draid": true, "draid1": true, "draid2": true, "draid3": true,
}

var zfsCompressions = map[string]bool{
	"": true, "on": true, "off": true, "lz4": true, "lzjb": true,
	"gzip": true, "zstd": true, "zstd-fast": true,
	"gzip-1": true, "gzip-2": true, "gzip-3": true, "gzip-4": true,
	"gzip-5": true, "gzip-6": true, "gzip-7": true, "gzip-8": true,
	"gzip-9": true,
}

var zfsRecordSizes = map[string]bool{
	"": true, "512": true, "1K": true, "2K": true, "4K": true, "8K": true,
	"16K": true, "32K": true, "64K": true, "128K": true, "256K": true,
	"512K": true, "1M": true,
}

var zfsDedupValues = map[string]bool{"": true, "on": true, "off": true, "verify": true, "sha256": true}

var zfsAclModes = map[string]bool{
	"": true, "discard": true, "groupmask": true, "passthrough": true, "restricted": true,
}

func validZfsPoolName(name string) bool {
	return zfsNameComponentRe.MatchString(name) && !strings.Contains(name, "..")
}

// validZfsDatasetName checks a full "pool/name[/sub]" dataset path.
func validZfsDatasetName(full string) bool {
	if full == "" || strings.HasPrefix(full, "/") || strings.HasSuffix(full, "/") {
		return false
	}
	for _, comp := range strings.Split(full, "/") {
		if !zfsNameComponentRe.MatchString(comp) || strings.Contains(comp, "..") {
			return false
		}
	}
	return true
}

func validZfsDevice(dev string) bool {
	return zfsWholeDiskRe.MatchString(dev) || zfsByIDRe.MatchString(dev)
}

func ValidateZfsPoolSpec(pool ZfsPoolSpec) error {
	if !validZfsPoolName(pool.Name) {
		return fmt.Errorf("invalid pool name %q", pool.Name)
	}
	if !zfsTopologies[pool.Topology] {
		return fmt.Errorf("pool %q: topology %q is not permitted", pool.Name, pool.Topology)
	}
	if !zfsCompressions[pool.Compression] {
		return fmt.Errorf("pool %q: compression %q is not permitted", pool.Name, pool.Compression)
	}
	for _, group := range [][]string{pool.DataDisks, pool.LogDisks, pool.CacheDisks, pool.SpareDisks} {
		for _, dev := range group {
			if !validZfsDevice(dev) {
				return fmt.Errorf("pool %q: device %q is not a whole-disk path", pool.Name, dev)
			}
		}
	}
	if len(pool.DataDisks) == 0 {
		return fmt.Errorf("pool %q: no data devices", pool.Name)
	}
	return nil
}

func ValidateZfsDatasetSpec(ds ZfsDatasetSpec) error {
	fullName := ds.Name
	if ds.Pool != "" {
		if !validZfsPoolName(ds.Pool) {
			return fmt.Errorf("invalid pool name %q", ds.Pool)
		}
		if !strings.HasPrefix(ds.Name, ds.Pool+"/") {
			fullName = ds.Pool + "/" + ds.Name
		}
	}
	if !validZfsDatasetName(fullName) {
		return fmt.Errorf("invalid dataset name %q", fullName)
	}
	if !zfsCompressions[ds.Compression] {
		return fmt.Errorf("dataset %q: compression %q is not permitted", fullName, ds.Compression)
	}
	if !zfsRecordSizes[ds.RecordSize] {
		return fmt.Errorf("dataset %q: recordsize %q is not permitted", fullName, ds.RecordSize)
	}
	if !zfsDedupValues[ds.Dedup] {
		return fmt.Errorf("dataset %q: dedup %q is not permitted", fullName, ds.Dedup)
	}
	if !zfsAclModes[ds.AclMode] {
		return fmt.Errorf("dataset %q: aclmode %q is not permitted", fullName, ds.AclMode)
	}
	if ds.Type != "" && ds.Type != "filesystem" && ds.Type != "zvol" {
		return fmt.Errorf("dataset %q: type %q is not permitted", fullName, ds.Type)
	}
	return nil
}
