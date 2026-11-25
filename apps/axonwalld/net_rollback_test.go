package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/axonwall/axonwall/apps/axonwalld/gen/agent/v1"
)

type fakeKernelState struct {
	Interfaces []ipAddrShowEntry  `json:"interfaces"`
	Routes     []ipRouteShowEntry `json:"routes"`
}

// TestNetRollbackHelperProcess emulates `ip`, `nft`, and `systemctl` in-process
// via os.Executable() wrappers so tests exercise real ApplyBundle / Rollback /
// Confirm / applyBootInterfaces paths without mutating host networking or requiring python3.
func TestNetRollbackHelperProcess(t *testing.T) {
	cmdName := os.Getenv("AXONWALL_FAKE_CMD")
	if cmdName == "" {
		return
	}

	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}

	if logFile := os.Getenv("AXONWALL_FAKE_LOG_FILE"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%s %s\n", cmdName, strings.Join(args, " "))
			_ = f.Close()
		}
	}

	switch cmdName {
	case "nft":
		if os.Getenv("AXONWALL_FAKE_NFT_FAIL") == "1" {
			fmt.Fprintln(os.Stderr, "fake nft error: injected failure")
			os.Exit(1)
		}
		if os.Getenv("AXONWALL_FAKE_NFT_FAIL_ROLLBACK") == "1" && len(args) >= 2 && args[0] == "-f" && strings.Contains(filepath.Base(args[1]), "axonwall-script-") {
			fmt.Fprintln(os.Stderr, "fake nft error: rollback apply failure")
			os.Exit(1)
		}
		if len(args) >= 2 && args[0] == "list" && args[1] == "ruleset" {
			fmt.Print(batch4NftScript)
		}
		os.Exit(0)
	case "systemctl":
		os.Exit(0)
	case "ip":
		os.Exit(runFakeIPCommand(os.Getenv("AXONWALL_FAKE_NET_STATE"), args))
	default:
		os.Exit(1)
	}
}

func runFakeIPCommand(statePath string, args []string) int {
	raw, err := os.ReadFile(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake ip: failed reading state: %v\n", err)
		return 1
	}
	var st fakeKernelState
	if err := json.Unmarshal(raw, &st); err != nil {
		fmt.Fprintf(os.Stderr, "fake ip: failed decoding state: %v\n", err)
		return 1
	}

	save := func() int {
		out, mErr := json.MarshalIndent(st, "", "  ")
		if mErr != nil {
			return 1
		}
		if wErr := os.WriteFile(statePath, out, 0600); wErr != nil {
			return 1
		}
		return 0
	}

	findDev := func(dev string) int {
		for i := range st.Interfaces {
			if st.Interfaces[i].Ifname == dev {
				return i
			}
		}
		return -1
	}

	parseCIDR := func(cidr string) (string, int, bool) {
		parts := strings.Split(strings.TrimSpace(cidr), "/")
		if len(parts) != 2 {
			return "", 0, false
		}
		p, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, false
		}
		return parts[0], p, true
	}

	// Query commands
	if slices.Equal(args, []string{"-j", "-4", "addr", "show"}) {
		out, _ := json.Marshal(st.Interfaces)
		fmt.Print(string(out))
		return 0
	}
	if slices.Equal(args, []string{"-j", "-4", "route", "show", "default"}) {
		out, _ := json.Marshal(st.Routes)
		fmt.Print(string(out))
		return 0
	}
	if len(args) == 4 && args[0] == "-4" && args[1] == "addr" && args[2] == "show" && args[3] != "" {
		// unused branch guard
	}
	if len(args) == 5 && args[0] == "-4" && args[1] == "addr" && args[2] == "show" && args[3] == "dev" {
		idx := findDev(args[4])
		if idx < 0 {
			return 1
		}
		ifc := st.Interfaces[idx]
		fmt.Printf("%d: %s: <%s> mtu 1500 state UP\n", idx+1, ifc.Ifname, strings.Join(ifc.Flags, ","))
		for _, a := range ifc.AddrInfo {
			line := fmt.Sprintf("    inet %s/%d scope %s", a.Local, a.Prefixlen, a.Scope)
			if a.Dynamic {
				line += " dynamic"
			}
			if a.Secondary {
				line += " secondary"
			}
			line += " " + ifc.Ifname
			fmt.Println(line)
		}
		return 0
	}

	// Link state
	if len(args) == 4 && args[0] == "link" && args[1] == "set" {
		dev, stateWord := args[2], args[3]
		idx := findDev(dev)
		if idx < 0 {
			st.Interfaces = append(st.Interfaces, ipAddrShowEntry{Ifname: dev, Flags: []string{"BROADCAST", "MULTICAST"}})
			idx = len(st.Interfaces) - 1
		}
		hasUp := slices.Contains(st.Interfaces[idx].Flags, "UP")
		if stateWord == "up" && !hasUp {
			st.Interfaces[idx].Flags = append(st.Interfaces[idx].Flags, "UP", "LOWER_UP")
		} else if stateWord == "down" {
			var filtered []string
			for _, f := range st.Interfaces[idx].Flags {
				if f != "UP" && f != "LOWER_UP" {
					filtered = append(filtered, f)
				}
			}
			st.Interfaces[idx].Flags = filtered
		}
		return save()
	}

	// Addr add / replace / del
	if len(args) == 5 && args[0] == "addr" && (args[1] == "replace" || args[1] == "add") && args[3] == "dev" {
		local, prefix, ok := parseCIDR(args[2])
		dev := args[4]
		idx := findDev(dev)
		if !ok || idx < 0 {
			return 1
		}
		replaced := false
		for i := range st.Interfaces[idx].AddrInfo {
			if st.Interfaces[idx].AddrInfo[i].Local == local && st.Interfaces[idx].AddrInfo[i].Prefixlen == prefix {
				st.Interfaces[idx].AddrInfo[i].Dynamic = false
				replaced = true
				break
			}
		}
		if !replaced {
			st.Interfaces[idx].AddrInfo = append(st.Interfaces[idx].AddrInfo, struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
				Scope     string `json:"scope"`
				Dynamic   bool   `json:"dynamic"`
				Secondary bool   `json:"secondary"`
			}{
				Family:    "inet",
				Local:     local,
				Prefixlen: prefix,
				Scope:     "global",
			})
		}
		return save()
	}

	if len(args) == 5 && args[0] == "addr" && args[1] == "del" && args[3] == "dev" {
		local, prefix, ok := parseCIDR(args[2])
		dev := args[4]
		idx := findDev(dev)
		if !ok || idx < 0 {
			return 1
		}
		kept := st.Interfaces[idx].AddrInfo[:0]
		found := false
		for _, a := range st.Interfaces[idx].AddrInfo {
			if a.Local == local && a.Prefixlen == prefix {
				found = true
				continue
			}
			kept = append(kept, a)
		}
		st.Interfaces[idx].AddrInfo = kept
		if !found {
			return 2
		}
		return save()
	}

	// Route replace / del default (single-hop and ECMP nexthop syntax)
	if len(args) >= 3 && args[0] == "route" && args[1] == "del" && args[2] == "default" {
		if slices.Contains(args[3:], "nexthop") {
			var kept []ipRouteShowEntry
			for _, r := range st.Routes {
				if len(r.Nexthops) > 0 {
					continue
				}
				kept = append(kept, r)
			}
			st.Routes = kept
			return save()
		}
		var gw, dev string
		for i := 3; i < len(args)-1; i++ {
			if args[i] == "via" {
				gw = args[i+1]
			} else if args[i] == "dev" {
				dev = args[i+1]
			}
		}
		var kept []ipRouteShowEntry
		for _, r := range st.Routes {
			matchGw := gw == "" || r.Gateway == gw
			matchDev := dev == "" || r.Dev == dev
			if matchGw && matchDev && len(r.Nexthops) == 0 {
				continue
			}
			kept = append(kept, r)
		}
		st.Routes = kept
		return save()
	}

	if len(args) >= 5 && args[0] == "route" && args[1] == "replace" && args[2] == "default" {
		if slices.Contains(args[3:], "nexthop") {
			type hopDef = struct {
				Gateway string `json:"gateway"`
				Dev     string `json:"dev"`
				Weight  int    `json:"weight"`
			}
			var hops []hopDef
			metric := 0
			var cur *hopDef
			for i := 3; i < len(args); i++ {
				switch args[i] {
				case "nexthop":
					hops = append(hops, hopDef{Weight: 1})
					cur = &hops[len(hops)-1]
				case "via":
					if i+1 < len(args) && cur != nil {
						cur.Gateway = args[i+1]
						i++
					}
				case "dev":
					if i+1 < len(args) && cur != nil {
						cur.Dev = args[i+1]
						i++
					}
				case "weight":
					if i+1 < len(args) && cur != nil {
						if w, err := strconv.Atoi(args[i+1]); err == nil && w > 0 {
							cur.Weight = w
						}
						i++
					}
				case "metric":
					if i+1 < len(args) {
						metric, _ = strconv.Atoi(args[i+1])
						i++
					}
				}
			}
			st.Routes = []ipRouteShowEntry{{
				Dst:      "default",
				Metric:   metric,
				Protocol: "static",
				Nexthops: hops,
			}}
			return save()
		}
		var gw, dev string
		metric := 0
		for i := 3; i < len(args)-1; i++ {
			if args[i] == "via" {
				gw = args[i+1]
			} else if args[i] == "dev" {
				dev = args[i+1]
			} else if args[i] == "metric" {
				metric, _ = strconv.Atoi(args[i+1])
			}
		}
		st.Routes = []ipRouteShowEntry{{
			Dst:      "default",
			Gateway:  gw,
			Dev:      dev,
			Metric:   metric,
			Protocol: "static",
		}}
		return save()
	}

	return 0
}

type netRollbackHarness struct {
	root          string
	etcDir        string
	persistEtcDir string
	stateDir      string
	bundleDir     string
	extDir        string
	netStateFile  string
	logFile       string
	server        *AgentServer
}

func setupNetRollbackHarness(t *testing.T, initial fakeKernelState) *netRollbackHarness {
	t.Helper()
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	persistEtcDir := filepath.Join(root, "persist-etc")
	stateDir := filepath.Join(root, "var")
	bundleDir := filepath.Join(root, "bundle")
	extDir := filepath.Join(root, "ext")
	binDir := filepath.Join(root, "bin")
	for _, d := range []string{etcDir, persistEtcDir, stateDir, bundleDir, extDir, binDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	netStateFile := filepath.Join(root, "kernel-net.json")
	stateBytes, err := json.MarshalIndent(initial, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netStateFile, stateBytes, 0600); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(root, "cmd.log")

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"ip", "nft", "systemctl"} {
		script := fmt.Sprintf("#!/bin/sh\nexec env AXONWALL_FAKE_CMD=%s AXONWALL_FAKE_NET_STATE=%q AXONWALL_FAKE_LOG_FILE=%q %q -test.run='^TestNetRollbackHelperProcess$' -- \"$@\"\n",
			cmd, netStateFile, logFile, exe)
		if err := os.WriteFile(filepath.Join(binDir, cmd), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}

	origPath := os.Getenv("PATH")
	origEtc := os.Getenv("AXONWALL_ETC_DIR")
	origState := os.Getenv("AXONWALL_STATE_DIR")
	origSrc := lkgConfigSrcDirs
	origDst := lkgConfigDstDirs
	origOwned := staticRoutesOwnedPath

	_ = os.Setenv("PATH", binDir+":"+origPath)
	_ = os.Setenv("AXONWALL_ETC_DIR", etcDir)
	_ = os.Setenv("AXONWALL_STATE_DIR", stateDir)
	lkgConfigSrcDirs = []string{persistEtcDir, etcDir}
	lkgConfigDstDirs = []string{etcDir, persistEtcDir}
	staticRoutesOwnedPath = filepath.Join(root, "owned-routes.json")

	t.Cleanup(func() {
		_ = os.Setenv("PATH", origPath)
		if origEtc == "" {
			_ = os.Unsetenv("AXONWALL_ETC_DIR")
		} else {
			_ = os.Setenv("AXONWALL_ETC_DIR", origEtc)
		}
		if origState == "" {
			_ = os.Unsetenv("AXONWALL_STATE_DIR")
		} else {
			_ = os.Setenv("AXONWALL_STATE_DIR", origState)
		}
		lkgConfigSrcDirs = origSrc
		lkgConfigDstDirs = origDst
		staticRoutesOwnedPath = origOwned
		_ = os.Remove("/run/axonwall/commit-confirm.pending")
	})

	s := &AgentServer{
		bundleDir:   bundleDir,
		sdwanProber: NewSDWanProber(),
		startTime:   time.Now(),
	}
	batch4StopTimer(t, s)

	return &netRollbackHarness{
		root:          root,
		etcDir:        etcDir,
		persistEtcDir: persistEtcDir,
		stateDir:      stateDir,
		bundleDir:     bundleDir,
		extDir:        extDir,
		netStateFile:  netStateFile,
		logFile:       logFile,
		server:        s,
	}
}

func (h *netRollbackHarness) readKernelState(t *testing.T) fakeKernelState {
	t.Helper()
	raw, err := os.ReadFile(h.netStateFile)
	if err != nil {
		t.Fatal(err)
	}
	var st fakeKernelState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func (h *netRollbackHarness) readCmdLog(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(h.logFile)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(raw)
}

func makeFakeAddr(local string, prefix int, dynamic, secondary bool) struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Prefixlen int    `json:"prefixlen"`
	Scope     string `json:"scope"`
	Dynamic   bool   `json:"dynamic"`
	Secondary bool   `json:"secondary"`
} {
	return struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
		Dynamic   bool   `json:"dynamic"`
		Secondary bool   `json:"secondary"`
	}{
		Family:    "inet",
		Local:     local,
		Prefixlen: prefix,
		Scope:     "global",
		Dynamic:   dynamic,
		Secondary: secondary,
	}
}

func TestNetRollbackAutoRevertsAddedInterfaceAndExternalFiles(t *testing.T) {
	initialNet := fakeKernelState{
		Interfaces: []ipAddrShowEntry{
			{
				Ifname:   "enp3s0",
				Flags:    []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("38.57.161.161", 24, true, false)},
			},
			{
				Ifname:   "enp5s0",
				Flags:    []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("10.60.0.1", 24, false, false)},
			},
			{
				Ifname:   "enp7s0",
				Flags:    []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("192.168.10.237", 24, true, false)},
			},
			{
				Ifname: "enp4s0",
				Flags:  []string{"BROADCAST", "MULTICAST"},
			},
		},
		Routes: []ipRouteShowEntry{
			{Dst: "default", Gateway: "38.57.161.1", Dev: "enp3s0", Protocol: "dhcp"},
		},
	}

	h := setupNetRollbackHarness(t, initialNet)

	// Pre-apply LKG configs and external files.
	origConf := "WAN_INTERFACE=enp3s0\nWAN_MODE=dhcp\nLAN_INTERFACE=enp5s0\nLAN_MODE=static\nLAN_IPV4_ADDRESS=10.60.0.1/24\nOPT1_INTERFACE=enp7s0\nOPT1_MODE=dhcp\nAXONWALL_INTERFACES=wan,lan,opt1\nIFACE_WAN_DEVICE=enp3s0\nIFACE_WAN_ROLE=wan\nIFACE_WAN_MODE=dhcp\nIFACE_LAN_DEVICE=enp5s0\nIFACE_LAN_ROLE=lan\nIFACE_LAN_MODE=static\nIFACE_LAN_IPV4_ADDRESS=10.60.0.1/24\nIFACE_OPT1_DEVICE=enp7s0\nIFACE_OPT1_ROLE=lan\nIFACE_OPT1_MODE=dhcp\n"
	origYaml := "interfaces:\n  - name: wan\n    role: wan\n    device: enp3s0\n    type: dhcp\n    enabled: true\n  - name: lan\n    role: lan\n    device: enp5s0\n    type: static\n    ipv4Address: 10.60.0.1/24\n    enabled: true\n  - name: opt1\n    role: lan\n    device: enp7s0\n    type: dhcp\n    enabled: true\n"
	if err := os.WriteFile(filepath.Join(h.etcDir, "interfaces.conf"), []byte(origConf), 0664); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "interfaces.yaml"), []byte(origYaml), 0660); err != nil {
		t.Fatal(err)
	}

	origDebIfaces := "# original /etc/network/interfaces\nauto lo\niface lo inet loopback\n"
	origKeaConf := "{\"Dhcp4\":{\"subnet4\":[{\"id\":1,\"subnet\":\"10.60.0.0/24\"}]}}"
	debIfacesPath := filepath.Join(h.extDir, "interfaces")
	keaConfPath := filepath.Join(h.extDir, "kea-dhcp4.conf")
	addedExtPath := filepath.Join(h.extDir, "added-by-candidate.conf")
	if err := os.WriteFile(debIfacesPath, []byte(origDebIfaces), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keaConfPath, []byte(origKeaConf), 0640); err != nil {
		t.Fatal(err)
	}

	// Candidate bundle adds opt3 on enp4s0 with overlapping 192.168.10.50/24 and mutates external files.
	candConf := origConf + "IFACE_OPT3_NAME=opt3\nIFACE_OPT3_DEVICE=enp4s0\nIFACE_OPT3_ROLE=lan\nIFACE_OPT3_MODE=static\nIFACE_OPT3_IPV4_ADDRESS=192.168.10.50/24\n"
	candYaml := origYaml + "  - name: opt3\n    role: lan\n    device: enp4s0\n    type: static\n    ipv4Address: 192.168.10.50/24\n    enabled: true\n"
	resp, err := h.server.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "ckpt-add-opt3",
		NftScript:             batch4NftScript + "# candidate\n",
		ConfirmTimeoutSeconds: 30,
		ReloadServices:        []string{"unbound", "kea-dhcp4-server"},
		Files: []*pb.BundleFile{
			{Path: filepath.Join(h.etcDir, "interfaces.conf"), Content: candConf, FileMode: 0664},
			{Path: filepath.Join(h.etcDir, "interfaces.yaml"), Content: candYaml, FileMode: 0660},
			{Path: filepath.Join(h.etcDir, "candidate-only.yaml"), Content: "extra: true\n", FileMode: 0660},
			{Path: debIfacesPath, Content: origDebIfaces + "auto enp4s0\n", FileMode: 0644},
			{Path: keaConfPath, Content: "{\"Dhcp4\":{\"subnet4\":[{\"id\":99}]}}", FileMode: 0640},
			{Path: addedExtPath, Content: "should-be-removed-on-rollback\n", FileMode: 0644},
		},
	})
	if err != nil {
		t.Fatalf("ApplyBundle failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("ApplyBundle returned failure: %s", resp.Message)
	}

	// Confirm candidate IP was temporarily applied onto enp4s0.
	midKernel := h.readKernelState(t)
	var midEnp4 ipAddrShowEntry
	for _, ifc := range midKernel.Interfaces {
		if ifc.Ifname == "enp4s0" {
			midEnp4 = ifc
		}
	}
	if !slices.Contains(midEnp4.Flags, "UP") || len(midEnp4.AddrInfo) != 1 || midEnp4.AddrInfo[0].Local != "192.168.10.50" {
		t.Fatalf("expected enp4s0 UP with 192.168.10.50/24 after ApplyBundle, got %+v", midEnp4)
	}

	// Simulate commit-confirm timer expiry calling triggerAutoRollback.
	h.server.mu.Lock()
	gen := h.server.rollbackGen
	h.server.mu.Unlock()
	h.server.triggerAutoRollback("ckpt-add-opt3", gen)

	afterKernel := h.readKernelState(t)
	byDev := make(map[string]ipAddrShowEntry)
	for _, ifc := range afterKernel.Interfaces {
		byDev[ifc.Ifname] = ifc
	}

	// 1. Newly added enp4s0 must be address-less and DOWN again.
	if slices.Contains(byDev["enp4s0"].Flags, "UP") || len(byDev["enp4s0"].AddrInfo) != 0 {
		t.Fatalf("expected enp4s0 DOWN with 0 addresses after rollback, got %+v", byDev["enp4s0"])
	}
	// 2. Existing WAN, LAN, OPT1 and default route remain intact.
	if len(byDev["enp3s0"].AddrInfo) != 1 || byDev["enp3s0"].AddrInfo[0].Local != "38.57.161.161" {
		t.Fatalf("expected enp3s0 intact after rollback, got %+v", byDev["enp3s0"])
	}
	if len(byDev["enp5s0"].AddrInfo) != 1 || byDev["enp5s0"].AddrInfo[0].Local != "10.60.0.1" {
		t.Fatalf("expected enp5s0 intact after rollback, got %+v", byDev["enp5s0"])
	}
	if len(byDev["enp7s0"].AddrInfo) != 1 || byDev["enp7s0"].AddrInfo[0].Local != "192.168.10.237" {
		t.Fatalf("expected enp7s0 intact after rollback, got %+v", byDev["enp7s0"])
	}
	if len(afterKernel.Routes) != 1 || afterKernel.Routes[0].Gateway != "38.57.161.1" || afterKernel.Routes[0].Dev != "enp3s0" {
		t.Fatalf("expected original default route intact after rollback, got %+v", afterKernel.Routes)
	}

	// 3. External files restored byte-for-byte; newly created external & LKG files deleted.
	gotDeb, err := os.ReadFile(debIfacesPath)
	if err != nil || string(gotDeb) != origDebIfaces {
		t.Fatalf("expected %s restored to %q, got %q (err=%v)", debIfacesPath, origDebIfaces, string(gotDeb), err)
	}
	gotKea, err := os.ReadFile(keaConfPath)
	if err != nil || string(gotKea) != origKeaConf {
		t.Fatalf("expected %s restored to %q, got %q (err=%v)", keaConfPath, origKeaConf, string(gotKea), err)
	}
	if _, err := os.Stat(addedExtPath); !os.IsNotExist(err) {
		t.Fatalf("expected newly added external file %s to be deleted on rollback", addedExtPath)
	}
	if _, err := os.Stat(filepath.Join(h.etcDir, "candidate-only.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected newly added YAML config to be deleted on rollback")
	}

	// 4. interfaces.conf & interfaces.yaml restored without enp4s0 / opt3.
	restoredYaml, err := os.ReadFile(filepath.Join(h.etcDir, "interfaces.yaml"))
	if err != nil || strings.Contains(string(restoredYaml), "enp4s0") || strings.Contains(string(restoredYaml), "opt3") {
		t.Fatalf("expected restored interfaces.yaml without enp4s0/opt3, got %q (err=%v)", string(restoredYaml), err)
	}

	// 5. Reloaded services (both unbound and kea-dhcp4-server) ran during rollback too.
	cmdLog := h.readCmdLog(t)
	if strings.Count(cmdLog, "systemctl --no-ask-password reload-or-restart unbound") < 2 {
		t.Fatalf("expected unbound reloaded during apply AND rollback, log:\n%s", cmdLog)
	}
	if strings.Count(cmdLog, "kea-dhcp4") < 2 {
		t.Fatalf("expected kea-dhcp4 service invoked during apply AND rollback, log:\n%s", cmdLog)
	}

	// 6. Pending rollback snapshots cleaned up.
	if _, err := os.Stat(liveNetSnapshotPath(h.bundleDir)); !os.IsNotExist(err) {
		t.Fatalf("expected lkg-net-snapshot.json removed after rollback")
	}
	if _, err := os.Stat(externalBundleDir(h.bundleDir)); !os.IsNotExist(err) {
		t.Fatalf("expected lkg-external dir removed after rollback")
	}
}

func TestNetRollbackRestoresModifiedStaticIPAndDefaultRoute(t *testing.T) {
	initialNet := fakeKernelState{
		Interfaces: []ipAddrShowEntry{
			{
				Ifname:   "enp3s0",
				Flags:    []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("38.57.161.161", 24, false, false)},
			},
			{
				Ifname:   "enp5s0",
				Flags:    []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("10.60.0.1", 24, false, false)},
			},
		},
		Routes: []ipRouteShowEntry{
			{Dst: "default", Gateway: "38.57.161.1", Dev: "enp3s0", Protocol: "static"},
		},
	}

	h := setupNetRollbackHarness(t, initialNet)

	origConf := "WAN_INTERFACE=enp3s0\nWAN_MODE=static\nWAN_IPV4_ADDRESS=38.57.161.161/24\nWAN_IPV4_GATEWAY=38.57.161.1\nLAN_INTERFACE=enp5s0\nLAN_MODE=static\nLAN_IPV4_ADDRESS=10.60.0.1/24\nAXONWALL_INTERFACES=wan,lan\nIFACE_WAN_DEVICE=enp3s0\nIFACE_WAN_ROLE=wan\nIFACE_WAN_MODE=static\nIFACE_WAN_IPV4_ADDRESS=38.57.161.161/24\nIFACE_WAN_IPV4_GATEWAY=38.57.161.1\nIFACE_LAN_DEVICE=enp5s0\nIFACE_LAN_ROLE=lan\nIFACE_LAN_MODE=static\nIFACE_LAN_IPV4_ADDRESS=10.60.0.1/24\n"
	origYaml := "interfaces:\n  - name: wan\n    role: wan\n    device: enp3s0\n    type: static\n    ipv4Address: 38.57.161.161/24\n    ipv4Gateway: 38.57.161.1\n    enabled: true\n  - name: lan\n    role: lan\n    device: enp5s0\n    type: static\n    ipv4Address: 10.60.0.1/24\n    enabled: true\n"
	_ = os.WriteFile(filepath.Join(h.etcDir, "interfaces.conf"), []byte(origConf), 0664)
	_ = os.WriteFile(filepath.Join(h.etcDir, "interfaces.yaml"), []byte(origYaml), 0660)

	// Candidate mutates LAN to 10.99.0.1/24 and replaces WAN gateway with unreachable 38.57.161.254.
	candConf := "WAN_INTERFACE=enp3s0\nWAN_MODE=static\nWAN_IPV4_ADDRESS=38.57.161.161/24\nWAN_IPV4_GATEWAY=38.57.161.254\nLAN_INTERFACE=enp5s0\nLAN_MODE=static\nLAN_IPV4_ADDRESS=10.99.0.1/24\nAXONWALL_INTERFACES=wan,lan\nIFACE_WAN_DEVICE=enp3s0\nIFACE_WAN_ROLE=wan\nIFACE_WAN_MODE=static\nIFACE_WAN_IPV4_ADDRESS=38.57.161.161/24\nIFACE_WAN_IPV4_GATEWAY=38.57.161.254\nIFACE_LAN_DEVICE=enp5s0\nIFACE_LAN_ROLE=lan\nIFACE_LAN_MODE=static\nIFACE_LAN_IPV4_ADDRESS=10.99.0.1/24\n"
	candYaml := "interfaces:\n  - name: wan\n    role: wan\n    device: enp3s0\n    type: static\n    ipv4Address: 38.57.161.161/24\n    ipv4Gateway: 38.57.161.254\n    enabled: true\n  - name: lan\n    role: lan\n    device: enp5s0\n    type: static\n    ipv4Address: 10.99.0.1/24\n    enabled: true\n"
	resp, err := h.server.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "mutate-static-gw",
		NftScript:             batch4NftScript + "# mutated\n",
		ConfirmTimeoutSeconds: 30,
		Files: []*pb.BundleFile{
			{Path: filepath.Join(h.etcDir, "interfaces.conf"), Content: candConf, FileMode: 0664},
			{Path: filepath.Join(h.etcDir, "interfaces.yaml"), Content: candYaml, FileMode: 0660},
		},
	})
	if err != nil || !resp.Success {
		t.Fatalf("ApplyBundle failed: err=%v resp=%+v", err, resp)
	}

	h.server.mu.Lock()
	err = h.server.executeRollback("manual test rollback")
	h.server.mu.Unlock()
	if err != nil {
		t.Fatalf("executeRollback failed: %v", err)
	}

	afterKernel := h.readKernelState(t)
	var enp5Addrs []string
	for _, ifc := range afterKernel.Interfaces {
		if ifc.Ifname == "enp5s0" {
			for _, a := range ifc.AddrInfo {
				enp5Addrs = append(enp5Addrs, fmt.Sprintf("%s/%d", a.Local, a.Prefixlen))
			}
		}
	}
	if !slices.Equal(enp5Addrs, []string{"10.60.0.1/24"}) {
		t.Fatalf("expected enp5s0 restored strictly to [10.60.0.1/24], got %v", enp5Addrs)
	}
	if len(afterKernel.Routes) != 1 || afterKernel.Routes[0].Gateway != "38.57.161.1" || afterKernel.Routes[0].Dev != "enp3s0" {
		t.Fatalf("expected default route restored to via 38.57.161.1 dev enp3s0, got %+v", afterKernel.Routes)
	}
}

func TestConfirmCleansPendingRollbackSnapshots(t *testing.T) {
	initialNet := fakeKernelState{
		Interfaces: []ipAddrShowEntry{
			{Ifname: "enp5s0", Flags: []string{"UP"}, AddrInfo: []struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
				Scope     string `json:"scope"`
				Dynamic   bool   `json:"dynamic"`
				Secondary bool   `json:"secondary"`
			}{makeFakeAddr("10.60.0.1", 24, false, false)}},
		},
	}
	h := setupNetRollbackHarness(t, initialNet)
	extFile := filepath.Join(h.extDir, "sample.conf")
	_ = os.WriteFile(extFile, []byte("before\n"), 0644)
	_ = os.WriteFile(filepath.Join(h.etcDir, "interfaces.conf"), []byte("LAN_INTERFACE=enp5s0\n"), 0664)

	resp, err := h.server.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "confirm-clean",
		NftScript:             batch4NftScript + "# new\n",
		ConfirmTimeoutSeconds: 30,
		Files: []*pb.BundleFile{
			{Path: filepath.Join(h.etcDir, "interfaces.conf"), Content: "LAN_INTERFACE=enp5s0\nLAN_MODE=static\n", FileMode: 0664},
			{Path: extFile, Content: "after\n", FileMode: 0644},
		},
	})
	if err != nil || !resp.Success {
		t.Fatalf("ApplyBundle failed: err=%v resp=%+v", err, resp)
	}
	if _, err := os.Stat(liveNetSnapshotPath(h.bundleDir)); err != nil {
		t.Fatalf("expected lkg-net-snapshot.json present while pending: %v", err)
	}
	if _, err := os.Stat(externalBundleMetaPath(h.bundleDir)); err != nil {
		t.Fatalf("expected lkg-external/meta.json present while pending: %v", err)
	}

	cResp, err := h.server.Confirm(context.Background(), &pb.ConfirmRequest{JobId: "confirm-clean"})
	if err != nil || !cResp.Success {
		t.Fatalf("Confirm failed: err=%v resp=%+v", err, cResp)
	}

	if _, err := os.Stat(liveNetSnapshotPath(h.bundleDir)); !os.IsNotExist(err) {
		t.Fatalf("expected lkg-net-snapshot.json deleted after Confirm")
	}
	if _, err := os.Stat(externalBundleDir(h.bundleDir)); !os.IsNotExist(err) {
		t.Fatalf("expected lkg-external removed after Confirm")
	}
	lkgConf, err := os.ReadFile(filepath.Join(h.bundleDir, "lkg-config", "interfaces.conf"))
	if err != nil || !strings.Contains(string(lkgConf), "LAN_MODE=static") {
		t.Fatalf("expected lkg-config/interfaces.conf updated to confirmed contents, got %q (err=%v)", string(lkgConf), err)
	}
}

func TestApplyBootInterfacesRemovesStaleLanStaticAddrAfterReplace(t *testing.T) {
	initialNet := fakeKernelState{
		Interfaces: []ipAddrShowEntry{
			{
				Ifname: "enp5s0",
				Flags:  []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{
					makeFakeAddr("10.60.0.1", 24, false, false),
					makeFakeAddr("10.60.0.254", 24, false, true), // secondary VIP
				},
			},
		},
	}
	h := setupNetRollbackHarness(t, initialNet)
	_ = os.WriteFile(filepath.Join(h.etcDir, "interfaces.conf"), []byte("LAN_INTERFACE=enp5s0\nLAN_MODE=static\nLAN_IPV4_ADDRESS=10.70.0.1/24\n"), 0664)

	if err := applyBootInterfaces(); err != nil {
		t.Fatalf("applyBootInterfaces failed: %v", err)
	}

	st := h.readKernelState(t)
	var addrs []string
	for _, a := range st.Interfaces[0].AddrInfo {
		addrs = append(addrs, fmt.Sprintf("%s/%d(sec=%v)", a.Local, a.Prefixlen, a.Secondary))
	}
	// Stale primary 10.60.0.1/24 removed AFTER replace succeeded; 10.70.0.1/24 and secondary VIP survive.
	if !slices.Contains(addrs, "10.70.0.1/24(sec=false)") || !slices.Contains(addrs, "10.60.0.254/24(sec=true)") || slices.Contains(addrs, "10.60.0.1/24(sec=false)") {
		t.Fatalf("unexpected addresses after LAN static replace: %v", addrs)
	}
	cmdLog := h.readCmdLog(t)
	repIdx := strings.Index(cmdLog, "ip addr replace 10.70.0.1/24 dev enp5s0")
	delIdx := strings.Index(cmdLog, "ip addr del 10.60.0.1/24 dev enp5s0")
	if repIdx < 0 || delIdx < 0 || delIdx < repIdx {
		t.Fatalf("expected ip addr replace before ip addr del, log:\n%s", cmdLog)
	}
}

func TestExecuteRollbackStillRestoresFilesAndNetWhenNftFailsOrMissing(t *testing.T) {
	initialNet := fakeKernelState{
		Interfaces: []ipAddrShowEntry{
			{
				Ifname: "enp5s0",
				Flags:  []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("10.60.0.1", 24, false, false)},
			},
			{
				Ifname: "enp4s0",
				Flags:  []string{"BROADCAST", "MULTICAST"},
			},
		},
	}

	h := setupNetRollbackHarness(t, initialNet)
	origYaml := "interfaces:\n  - name: lan\n    role: lan\n    device: enp5s0\n    type: static\n    ipv4Address: 10.60.0.1/24\n    enabled: true\n"
	origConf := "LAN_INTERFACE=enp5s0\nLAN_MODE=static\nLAN_IPV4_ADDRESS=10.60.0.1/24\n"
	_ = os.WriteFile(filepath.Join(h.etcDir, "interfaces.conf"), []byte(origConf), 0664)
	_ = os.WriteFile(filepath.Join(h.etcDir, "interfaces.yaml"), []byte(origYaml), 0660)
	extFile := filepath.Join(h.extDir, "interfaces")
	_ = os.WriteFile(extFile, []byte("orig-ext\n"), 0644)

	// Subcase A: ApplyBundle succeeds (so lkg snapshots exist), then rollback nft -f fails.
	resp, err := h.server.ApplyBundle(context.Background(), &pb.ApplyBundleRequest{
		JobId:                 "nft-fail-rb",
		NftScript:             batch4NftScript + "# cand\n",
		ConfirmTimeoutSeconds: 30,
		Files: []*pb.BundleFile{
			{Path: filepath.Join(h.etcDir, "interfaces.yaml"), Content: origYaml + "  - name: opt3\n    role: lan\n    device: enp4s0\n    type: static\n    ipv4Address: 10.88.0.1/24\n    enabled: true\n", FileMode: 0660},
			{Path: filepath.Join(h.etcDir, "interfaces.conf"), Content: origConf + "IFACE_OPT3_NAME=opt3\nIFACE_OPT3_DEVICE=enp4s0\nIFACE_OPT3_ROLE=lan\nIFACE_OPT3_MODE=static\nIFACE_OPT3_IPV4_ADDRESS=10.88.0.1/24\n", FileMode: 0664},
			{Path: extFile, Content: "cand-ext\n", FileMode: 0644},
		},
	})
	if err != nil || !resp.Success {
		t.Fatalf("ApplyBundle failed: err=%v resp=%+v", err, resp)
	}

	t.Setenv("AXONWALL_FAKE_NFT_FAIL_ROLLBACK", "1")
	h.server.mu.Lock()
	rbErr := h.server.executeRollback("test nft fail")
	h.server.mu.Unlock()
	if rbErr == nil {
		t.Fatalf("expected executeRollback to report nftables apply error")
	}

	// Config files, external files, and live kernel state MUST still be restored!
	gotYaml, _ := os.ReadFile(filepath.Join(h.etcDir, "interfaces.yaml"))
	if strings.Contains(string(gotYaml), "opt3") || !strings.Contains(string(gotYaml), "10.60.0.1/24") {
		t.Fatalf("interfaces.yaml was not restored when nft rollback failed: %s", string(gotYaml))
	}
	gotExt, _ := os.ReadFile(extFile)
	if string(gotExt) != "orig-ext\n" {
		t.Fatalf("external file was not restored when nft rollback failed: %q", string(gotExt))
	}
	afterKernel := h.readKernelState(t)
	for _, ifc := range afterKernel.Interfaces {
		if ifc.Ifname == "enp4s0" && (len(ifc.AddrInfo) > 0 || slices.Contains(ifc.Flags, "UP")) {
			t.Fatalf("enp4s0 was not rolled back when nft rollback failed: %+v", ifc)
		}
	}

	// Subcase B: lastGoodScript == "" with snapshots on disk still restores snapshots before returning error.
	snapshotLkgConfig(h.bundleDir)
	captureLiveNetSnapshot(h.bundleDir)
	snapshotExternalBundleFiles(h.bundleDir, []validatedBundleFile{{cleanPath: extFile}}, false)
	_ = os.WriteFile(extFile, []byte("mutated-without-lkg-script\n"), 0644)
	_ = os.Remove(filepath.Join(h.bundleDir, "last-known-good.nft"))
	h.server.mu.Lock()
	h.server.lastGoodScript = ""
	h.server.pendingConfirm = true
	h.server.pendingJobID = "no-script-job"
	rbErr2 := h.server.executeRollback("missing lkg script")
	h.server.mu.Unlock()
	if rbErr2 == nil {
		t.Fatalf("expected executeRollback to return error when lastGoodScript is empty")
	}
	gotExt2, _ := os.ReadFile(extFile)
	if string(gotExt2) != "orig-ext\n" {
		t.Fatalf("external file was not restored when lastGoodScript was empty: %q", string(gotExt2))
	}
	if h.server.pendingConfirm || h.server.pendingJobID != "" {
		t.Fatalf("expected pending confirm state cleared on rollback without script")
	}
}

func TestIsDynamicVirtualIfaceSkipsOverlaysAndKeepsPhysical(t *testing.T) {
	shouldSkip := []string{"tailscale0", "wg0", "wg-corp", "veth1234", "tap100i0", "cni0", "flannel.1", "cilium_host", "lxc101", "virbr0", "vmbr0", "tun0", "xfrm1", "br-lan"}
	for _, dev := range shouldSkip {
		if !isDynamicVirtualIface(dev) {
			t.Errorf("expected isDynamicVirtualIface(%q) = true", dev)
		}
	}
	shouldKeep := []string{"enp4s0", "eth0", "ens3", "eno1", "enp7s0.20", "bond0"}
	for _, dev := range shouldKeep {
		if isDynamicVirtualIface(dev) {
			t.Errorf("expected isDynamicVirtualIface(%q) = false", dev)
		}
	}

	// Verify restoreLiveNetSnapshot never deletes/downs tailscale0 or wg0 that came up post-snapshot.
	initialNet := fakeKernelState{
		Interfaces: []ipAddrShowEntry{
			{
				Ifname: "enp5s0",
				Flags:  []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("10.60.0.1", 24, false, false)},
			},
		},
	}
	h := setupNetRollbackHarness(t, initialNet)
	captureLiveNetSnapshot(h.bundleDir)

	// Simulate tailscale0 and wg0 coming up during confirm window.
	st := h.readKernelState(t)
	st.Interfaces = append(st.Interfaces,
		ipAddrShowEntry{
			Ifname: "tailscale0",
			Flags:  []string{"POINTOPOINT", "UP", "LOWER_UP"},
			AddrInfo: []struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
				Scope     string `json:"scope"`
				Dynamic   bool   `json:"dynamic"`
				Secondary bool   `json:"secondary"`
			}{makeFakeAddr("100.64.0.10", 32, false, false)},
		},
		ipAddrShowEntry{
			Ifname: "wg0",
			Flags:  []string{"POINTOPOINT", "UP", "LOWER_UP"},
			AddrInfo: []struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
				Scope     string `json:"scope"`
				Dynamic   bool   `json:"dynamic"`
				Secondary bool   `json:"secondary"`
			}{makeFakeAddr("10.99.0.1", 24, false, false)},
		},
	)
	raw, _ := json.MarshalIndent(st, "", "  ")
	_ = os.WriteFile(h.netStateFile, raw, 0600)

	if ok := restoreLiveNetSnapshot(h.bundleDir); !ok {
		t.Fatalf("restoreLiveNetSnapshot failed")
	}

	after := h.readKernelState(t)
	found := map[string]bool{}
	for _, ifc := range after.Interfaces {
		if ifc.Ifname == "tailscale0" || ifc.Ifname == "wg0" {
			found[ifc.Ifname] = true
			if !slices.Contains(ifc.Flags, "UP") || len(ifc.AddrInfo) != 1 {
				t.Fatalf("dynamic virtual interface %s was altered during rollback: %+v", ifc.Ifname, ifc)
			}
		}
	}
	if !found["tailscale0"] || !found["wg0"] {
		t.Fatalf("expected dynamic interfaces preserved after rollback, found=%v", found)
	}
}

func TestLiveNetSnapshotPreservesMultipathNexthopDefaultRoutes(t *testing.T) {
	initialNet := fakeKernelState{
		Interfaces: []ipAddrShowEntry{
			{
				Ifname: "enp3s0",
				Flags:  []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("38.57.161.161", 24, false, false)},
			},
			{
				Ifname: "enp7s0",
				Flags:  []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
				AddrInfo: []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
					Dynamic   bool   `json:"dynamic"`
					Secondary bool   `json:"secondary"`
				}{makeFakeAddr("198.51.100.10", 24, false, false)},
			},
		},
		Routes: []ipRouteShowEntry{
			{
				Dst:      "default",
				Metric:   10,
				Protocol: "static",
				Nexthops: []struct {
					Gateway string `json:"gateway"`
					Dev     string `json:"dev"`
					Weight  int    `json:"weight"`
				}{
					{Gateway: "38.57.161.1", Dev: "enp3s0", Weight: 2},
					{Gateway: "198.51.100.1", Dev: "enp7s0", Weight: 1},
				},
			},
		},
	}

	h := setupNetRollbackHarness(t, initialNet)
	captureLiveNetSnapshot(h.bundleDir)

	// Candidate replaces ECMP multipath default route with a broken single-hop default route.
	mut := h.readKernelState(t)
	mut.Routes = []ipRouteShowEntry{{Dst: "default", Gateway: "10.255.255.1", Dev: "enp3s0", Protocol: "static"}}
	raw, _ := json.MarshalIndent(mut, "", "  ")
	_ = os.WriteFile(h.netStateFile, raw, 0600)

	if ok := restoreLiveNetSnapshot(h.bundleDir); !ok {
		t.Fatalf("restoreLiveNetSnapshot failed")
	}

	after := h.readKernelState(t)
	if len(after.Routes) != 1 || len(after.Routes[0].Nexthops) != 2 {
		t.Fatalf("expected ECMP multipath default route with 2 nexthops restored, got %+v", after.Routes)
	}
	if after.Routes[0].Nexthops[0].Gateway != "38.57.161.1" || after.Routes[0].Nexthops[1].Gateway != "198.51.100.1" {
		t.Fatalf("restored multipath nexthops mismatch: %+v", after.Routes[0].Nexthops)
	}
}

func TestStaleStaticAddrsDetectsPrefixChange(t *testing.T) {
	addrShow := "2: enp5s0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 10.60.0.1/24 scope global enp5s0\n"
	got := staleStaticAddrs(addrShow, "10.60.0.1/25")
	if !slices.Equal(got, []string{"10.60.0.1/24"}) {
		t.Fatalf("expected staleStaticAddrs to return [10.60.0.1/24] on /24->/25 prefix change, got %v", got)
	}
}

func TestCancelPostBootVerificationCancelsArmedVerifier(t *testing.T) {
	origDelays := postBootVerificationDelays
	origReconcile := postBootReconcileStaticRoutes
	postBootVerificationDelays = []time.Duration{40 * time.Millisecond}
	var calls atomic.Int32
	postBootReconcileStaticRoutes = func() error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() {
		cancelPostBootVerification()
		postBootVerificationDelays = origDelays
		postBootReconcileStaticRoutes = origReconcile
	})

	schedulePostBootVerification([]bootIfaceSpec{{Name: "opt3", Device: "enp4s0", Role: "lan", Mode: "dhcp"}})
	cancelPostBootVerification()
	time.Sleep(120 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("expected 0 verifier rounds after cancelPostBootVerification, got %d", got)
	}
}
