package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBugHunt4_LimitOverFlagNetlink(t *testing.T) {
	lineOver := `tcp dport 2222 limit rate over 50/second drop`
	specOver, err := compileRuleTokens("input", lineOver, NftRuleSpec{}, strings.Fields(lineOver))
	if err != nil {
		t.Fatalf("compileRuleTokens(over): %v", err)
	}
	exprsOver := bytes.Join(specOver.Expressions, nil)

	lineUnder := `tcp dport 2222 limit rate 50/second drop`
	specUnder, err := compileRuleTokens("input", lineUnder, NftRuleSpec{}, strings.Fields(lineUnder))
	if err != nil {
		t.Fatalf("compileRuleTokens(under): %v", err)
	}
	exprsUnder := bytes.Join(specUnder.Expressions, nil)

	// nftaLimitFlags = 5 | nlaFNetByteorder (0x4000) -> LE uint16 type = 0x4005, value BE uint32 = 1
	wantAttr := nlAttrU32BE(nftaLimitFlags, nftLimitFInv)
	if !bytes.Contains(exprsOver, wantAttr) {
		t.Fatalf("expected limit over rule to include NFTA_LIMIT_FLAGS=NFT_LIMIT_F_INV")
	}
	if bytes.Contains(exprsUnder, wantAttr) {
		t.Fatalf("non-inverted limit rule must not include NFT_LIMIT_F_INV")
	}
}

func TestBugHunt4_WildcardIfnameNetlink(t *testing.T) {
	wild, err := encodeIfnameBytes("wg*")
	if err != nil {
		t.Fatalf("encodeIfnameBytes(wg*): %v", err)
	}
	if string(wild) != "wg" || len(wild) != 2 {
		t.Fatalf("wildcard wg* encoded as %q (len=%d), want prefix bytes \"wg\" without trailing * or NUL", wild, len(wild))
	}

	exact, err := encodeIfnameBytes("eth0")
	if err != nil {
		t.Fatalf("encodeIfnameBytes(eth0): %v", err)
	}
	if !bytes.Equal(exact, []byte("eth0\x00")) {
		t.Fatalf("exact eth0 encoded as %x, want NUL-terminated", exact)
	}

	if _, err := encodeIfnameBytes(strings.Repeat("a", 16)); err == nil {
		t.Fatalf("expected IFNAMSIZ >= 16 interface name to error")
	}
	if _, err := encodeIfnameBytes("*"); err == nil {
		t.Fatalf("expected bare * wildcard to error")
	}
}

func TestBugHunt4_SetElemChunkingNoUint16Overflow(t *testing.T) {
	elems := make([]NftSetElement, 2100)
	for i := range elems {
		elems[i] = NftSetElement{
			Key: []byte{10, byte(i >> 16), byte(i >> 8), byte(i)},
			End: []byte{10, byte(i >> 16), byte(i >> 8), byte(i + 1)},
		}
	}
	batch := &NftCompiledBatch{
		TableName: "axonwall",
		Sets: []NftSetSpec{
			{Name: "blocked_ips", SetID: 1, KeyType: "ipv4_addr", KeyLen: 4, Interval: true, Elements: elems},
		},
	}
	msgs := serializeNftBatch(batch)
	newElemCount := 0
	for _, m := range msgs {
		msgType := binary.LittleEndian.Uint16(m[4:6])
		if msgType == nftMsgType(nftMsgNewSetElem) {
			newElemCount++
			if len(m) > 0xffff {
				t.Fatalf("chunked set elem netlink msg too large: %d", len(m))
			}
		}
	}
	if newElemCount < 5 {
		t.Fatalf("expected >= 5 chunked NFT_MSG_NEWSETELEM messages for 2100 elements, got %d", newElemCount)
	}
	if _, err := nlAttrChecked(1, make([]byte, 70000)); err == nil {
		t.Fatalf("expected nlAttrChecked to reject >65535 byte attribute")
	}
}

func TestBugHunt4_RestoreFleetBlocksSubSecondTTL(t *testing.T) {
	e := NewNftablesEngine()
	e.fleetBlocksPath = filepath.Join(t.TempDir(), "fleet-blocks.json")
	past := time.Now().Add(-500 * time.Millisecond)
	soon := time.Now().Add(400 * time.Millisecond)
	entries := []fleetBlockEntry{
		{Target: "203.0.113.10", SetName: "blocked_ips", ExpiresAt: past},
		{Target: "203.0.113.11", SetName: "blocked_ips", ExpiresAt: soon},
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.fleetBlocksPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.mu.Lock()
		for _, ent := range e.fleetBlocks {
			if ent.timer != nil {
				ent.timer.Stop()
			}
		}
		e.mu.Unlock()
	})

	e.RestoreFleetBlocks()
	e.mu.Lock()
	_, hasExpired := e.fleetBlocks[fleetBlockKey("blocked_ips", "203.0.113.10")]
	subsec, hasSubsec := e.fleetBlocks[fleetBlockKey("blocked_ips", "203.0.113.11")]
	e.mu.Unlock()
	if hasExpired {
		t.Fatalf("expired fleet block should not be restored")
	}
	if !hasSubsec || subsec == nil || subsec.timer == nil {
		t.Fatalf("expected <1s remaining TTL block to retain an expiry timer instead of turning permanent: %+v", subsec)
	}
}

func TestBugHunt4_DemoteStandbyRollbackDoesNotUnfence(t *testing.T) {
	ha := NewEdgeHAEngine("hosted", "standby")
	// Already standby; failing RemoveAddress must NOT attempt SetLinkUp(wan, true)
	err := ha.Demote(NewEdgeNetworkEngine(), EdgeHATransitionPayload{
		WanDevice: "eth99nonexistent",
		LanDevice: "eth98nonexistent",
		LanVipV4:  "192.0.2.1/24",
	})
	if err == nil {
		t.Fatalf("expected Demote on nonexistent devices to fail")
	}
	if strings.Contains(err.Error(), "rollback failed to restore WAN") {
		t.Fatalf("standby Demote rollback attempted to unfence WAN: %v", err)
	}

	netEng := NewEdgeNetworkEngine()
	if _, err := net.ParseMAC("invalid-mac"); err == nil {
		t.Fatal("sanity")
	}
	if err := netEng.SetLinkMAC("eth0", "invalid-mac"); err == nil {
		t.Fatalf("expected SetLinkMAC to reject invalid MAC")
	}
	if err := netEng.ConfigureInterface(EdgeInterfaceSpec{Name: "wan", Device: "eth99nonexistent", Enabled: false}); err == nil {
		t.Fatalf("expected disabled ConfigureInterface on missing device to return error")
	}
}

func TestBugHunt4_CloudInitAllowlistAndJSON(t *testing.T) {
	root := t.TempDir()
	cfg := &EdgeBootConfig{}
	if err := writeCloudInitFile(cfg, CloudInitWriteFile{Path: "/etc/hosts.allow", Content: "ALL: ALL\n"}, root); err == nil {
		t.Fatalf("expected /etc/hosts.allow prefix bypass to be rejected")
	}
	if err := writeCloudInitFile(cfg, CloudInitWriteFile{Path: "/etc/nftables.conf.d/evil.nft", Content: "flush ruleset\n"}, root); err == nil {
		t.Fatalf("expected /etc/nftables.conf.d/ prefix bypass to be rejected")
	}
	if err := writeCloudInitFile(cfg, CloudInitWriteFile{Path: "/etc/hosts", Content: "127.0.0.1 localhost\n"}, root); err != nil {
		t.Fatalf("expected exact /etc/hosts to be permitted: %v", err)
	}

	rawJSON := `{"insecure_bootstrap": true, "ca_cert": "CERTDATA", "write_files": [{"path": "/etc/axonwall/test.conf", "content": "ok=1\n"}]}`
	if err := applyCloudInitJSON(cfg, rawJSON, root); err != nil {
		t.Fatalf("applyCloudInitJSON: %v", err)
	}
	if !cfg.InsecureBootstrap {
		t.Fatalf("expected top-level JSON bool insecure_bootstrap to apply")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/axonwall/certs/ca.crt")); err != nil {
		t.Fatalf("expected JSON ca_cert written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/axonwall/test.conf")); err != nil {
		t.Fatalf("expected JSON write_files entry written: %v", err)
	}
}
