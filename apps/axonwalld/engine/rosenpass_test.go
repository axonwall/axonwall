package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRosenpassPluginDefinition(t *testing.T) {
	defs := GetExtensionPluginDefinitions()
	found := false
	for _, d := range defs {
		if d.ID == "rosenpass" {
			found = true
			if len(d.SystemdUnits) == 0 || d.SystemdUnits[0] != "rosenpass.service" {
				t.Fatalf("expected rosenpass.service in SystemdUnits, got %v", d.SystemdUnits)
			}
			break
		}
	}
	if !found {
		t.Fatal("rosenpass not found in GetExtensionPluginDefinitions()")
	}
}

func TestGenerateAndRotateRosenpassKeypair(t *testing.T) {
	tmpDir := t.TempDir()

	sha1, size1, err := GenerateRosenpassKeypair(tmpDir, false)
	if err != nil {
		t.Fatalf("GenerateRosenpassKeypair failed: %v", err)
	}
	if len(sha1) != 64 {
		t.Fatalf("expected 64-char SHA-256 hex digest, got %q", sha1)
	}
	if size1 <= 0 {
		t.Fatalf("expected positive public key size, got %d", size1)
	}

	skInfo, err := os.Stat(filepath.Join(tmpDir, "pq.sk"))
	if err != nil {
		t.Fatalf("pq.sk missing: %v", err)
	}
	if skInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected pq.sk permissions 0600, got %o", skInfo.Mode().Perm())
	}

	// Calling without force should return the same key
	shaSame, _, err := GenerateRosenpassKeypair(tmpDir, false)
	if err != nil {
		t.Fatalf("second GenerateRosenpassKeypair(force=false) failed: %v", err)
	}
	if shaSame != sha1 {
		t.Fatalf("expected identical key when force=false, got %s vs %s", shaSame, sha1)
	}

	// Calling with force=true should rotate the keypair
	sha2, _, err := GenerateRosenpassKeypair(tmpDir, true)
	if err != nil {
		t.Fatalf("GenerateRosenpassKeypair(force=true) failed: %v", err)
	}
	if sha2 == sha1 {
		t.Fatalf("expected rotated keypair with force=true to have new SHA-256, got identical %s", sha2)
	}
}

func TestSaveRosenpassPeerPublicKeyValidation(t *testing.T) {
	tmpDir := t.TempDir()

	// Reject path traversal
	for _, badName := range []string{"../evil", "foo/bar", "peer..1", "", "peer space"} {
		if _, _, _, err := SaveRosenpassPeerPublicKey(tmpDir, badName, []byte("testkey")); err == nil {
			t.Fatalf("expected error for invalid peer name %q", badName)
		}
	}

	rawKey := make([]byte, 1024)
	for i := range rawKey {
		rawKey[i] = byte(i % 251)
	}
	savedPath, shaHex, sizeBytes, err := SaveRosenpassPeerPublicKey(tmpDir, "beta-node_01", rawKey)
	if err != nil {
		t.Fatalf("SaveRosenpassPeerPublicKey failed: %v", err)
	}
	if sizeBytes != 1024 || len(shaHex) != 64 {
		t.Fatalf("unexpected sizeBytes=%d or shaHex=%q", sizeBytes, shaHex)
	}
	info, err := os.Stat(savedPath)
	if err != nil {
		t.Fatalf("saved peer key missing: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 on peer public key, got %o", info.Mode().Perm())
	}
}

func TestParseWgPresharedKeysZeroLeakage(t *testing.T) {
	rawSecretPsk := "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
	pskOut := strings.Join([]string{
		"PeerActivePQKeyBase64Here000000000000000000=\t" + rawSecretPsk,
		"PeerNoneKeyBase64Here0000000000000000000000=\t(none)",
		"PeerZeroKeyBase64Here0000000000000000000000=\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}, "\n")
	hsOut := "PeerActivePQKeyBase64Here000000000000000000=\t1730000120\n"

	peers := ParseWgPresharedKeysOutput(pskOut, hsOut)
	if len(peers) != 3 {
		t.Fatalf("expected 3 parsed peers, got %d", len(peers))
	}

	if peers[0].PskStatus != "active_pq_psk" {
		t.Fatalf("expected first peer active_pq_psk, got %s", peers[0].PskStatus)
	}
	if len(peers[0].PskSha256Prefix) != 16 {
		t.Fatalf("expected 16-char SHA-256 prefix, got %q", peers[0].PskSha256Prefix)
	}
	if peers[0].PskSha256Prefix == rawSecretPsk || strings.Contains(peers[0].PskSha256Prefix, "K7gNU3") {
		t.Fatalf("raw PSK leaked into telemetry output!")
	}
	if peers[0].LatestHandshakeUnix != 1730000120 {
		t.Fatalf("expected handshake timestamp 1730000120, got %d", peers[0].LatestHandshakeUnix)
	}

	if peers[1].PskStatus != "unseeded_classical_only" || peers[1].PskSha256Prefix != "" {
		t.Fatalf("expected second peer unseeded_classical_only, got %+v", peers[1])
	}
	if peers[2].PskStatus != "unseeded_classical_only" || peers[2].PskSha256Prefix != "" {
		t.Fatalf("expected third peer (all zeros) unseeded_classical_only, got %+v", peers[2])
	}
}
