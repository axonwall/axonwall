package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axonwall/axonwall/apps/axonwall-satellite/engine"
)

func TestSecH05_PID1AppliesBaselineNftBeforeWANAndIMDS(t *testing.T) {
	root := t.TempDir()
	var events []string
	var appliedScripts []string
	var forwardingStates []bool

	deps := pid1BootstrapDeps{
		applyNft: func(script string) error {
			events = append(events, "applyNft")
			appliedScripts = append(appliedScripts, script)
			return nil
		},
		confirmNft: func() {
			events = append(events, "confirmNft")
		},
		restoreFleet: func() {
			events = append(events, "restoreFleet")
		},
		setForwarding: func(enabled bool) error {
			events = append(events, fmt.Sprintf("setForwarding:%v", enabled))
			forwardingStates = append(forwardingStates, enabled)
			return nil
		},
		discoverPrimaryNIC: func() string {
			events = append(events, "discoverPrimaryNIC")
			return "eth0"
		},
		configureInterface: func(spec engine.EdgeInterfaceSpec) error {
			events = append(events, "configureInterface:"+spec.Device+":"+spec.Address)
			return nil
		},
		addRoute: func(rt engine.EdgeRouteSpec) error {
			events = append(events, "addRoute:"+rt.Destination)
			return nil
		},
		fetchIMDS: func(ctx context.Context, baseURL string) (engine.CloudInitPayload, bool) {
			events = append(events, "fetchIMDS:"+baseURL)
			return engine.CloudInitPayload{
				Datasource: "imds-ec2",
				UserData:   "#cloud-config\naxonwall:\n  hub: wss://10.0.0.2:2966/ws/satellite\n  token: ztp_imds_boot\n  id: edge-imds-01\n",
			}, true
		},
		mergeCloudInit: engine.MergeCloudInitIntoBootConfig,
		setHostname: func(name []byte) error {
			events = append(events, "setHostname:"+string(name))
			return nil
		},
		nftConfPath: filepath.Join(root, "etc", "nftables.conf"),
		rootDir:     root,
	}

	bootCfg := engine.ParseKernelCmdline("")
	baselineScript, baselineApplied := applyPID1BaselineNft(defaultCoreURL, deps)
	if !baselineApplied {
		t.Fatalf("expected baseline nftables apply to succeed")
	}
	bootstrapPID1InterfacesAndIMDS(&bootCfg, defaultCoreURL, "", deps)
	finalizePID1Nft(bootCfg.HubURL, baselineScript, baselineApplied, deps)

	if len(events) < 6 {
		t.Fatalf("unexpectedly short event sequence: %v", events)
	}
	// Baseline fail-closed nftables and confirm MUST happen before WAN DHCPv4 and IMDS.
	applyIdx, confirmIdx, dhcpIdx, imdsIdx := -1, -1, -1, -1
	for i, ev := range events {
		switch {
		case ev == "applyNft" && applyIdx == -1:
			applyIdx = i
		case ev == "confirmNft" && confirmIdx == -1:
			confirmIdx = i
		case strings.HasPrefix(ev, "configureInterface:eth0:dhcp") && dhcpIdx == -1:
			dhcpIdx = i
		case strings.HasPrefix(ev, "fetchIMDS:") && imdsIdx == -1:
			imdsIdx = i
		}
	}
	if applyIdx < 0 || confirmIdx < 0 || dhcpIdx < 0 || imdsIdx < 0 {
		t.Fatalf("missing expected boot events in %v", events)
	}
	if !(applyIdx < confirmIdx && confirmIdx < dhcpIdx && dhcpIdx < imdsIdx) {
		t.Fatalf("expected applyNft < confirmNft < WAN DHCPv4 < fetchIMDS; got events: %v", events)
	}
	if !strings.Contains(appliedScripts[0], "policy drop;") {
		t.Fatalf("expected baseline script to be fail-closed (policy drop), got:\n%s", appliedScripts[0])
	}
	if len(forwardingStates) < 2 || forwardingStates[0] != false || !forwardingStates[len(forwardingStates)-1] {
		t.Fatalf("expected IP forwarding to stay false during WAN/IMDS bootstrap and enable only at finalize, got %v", forwardingStates)
	}
}

func TestSecH05_PID1SkipsIMDSWhenCmdlineOrFlagsSupplyHubOrToken(t *testing.T) {
	cases := []struct {
		name      string
		cmdline   string
		flagCore  string
		flagToken string
		wantProbe bool
	}{
		{
			name:      "cmdline hub only does not probe IMDS",
			cmdline:   "axonwall.hub=wss://hub.example:2966/ws/satellite",
			flagCore:  defaultCoreURL,
			flagToken: "",
			wantProbe: false,
		},
		{
			name:      "cmdline token only does not probe IMDS",
			cmdline:   "axonwall.token=ztp_cmdline_only",
			flagCore:  defaultCoreURL,
			flagToken: "",
			wantProbe: false,
		},
		{
			name:      "cmdline hub and token does not probe IMDS",
			cmdline:   "axonwall.hub=wss://hub.example:2966/ws/satellite axonwall.token=ztp_cmdline",
			flagCore:  defaultCoreURL,
			flagToken: "",
			wantProbe: false,
		},
		{
			name:      "CLI core flag does not probe IMDS",
			cmdline:   "",
			flagCore:  "wss://cli-hub.example:2966/ws/satellite",
			flagToken: "",
			wantProbe: false,
		},
		{
			name:      "CLI token flag does not probe IMDS",
			cmdline:   "",
			flagCore:  defaultCoreURL,
			flagToken: "ztp_cli_only",
			wantProbe: false,
		},
		{
			name:      "empty hub and token probes IMDS",
			cmdline:   "",
			flagCore:  defaultCoreURL,
			flagToken: "",
			wantProbe: true,
		},
		{
			name:      "cmdline hub with axonwall.imds=1 probes IMDS",
			cmdline:   "axonwall.hub=wss://hub.example:2966/ws/satellite axonwall.imds=1",
			flagCore:  defaultCoreURL,
			flagToken: "",
			wantProbe: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			probed := false
			deps := pid1BootstrapDeps{
				applyNft:           func(string) error { return nil },
				confirmNft:         func() {},
				restoreFleet:       func() {},
				setForwarding:      func(bool) error { return nil },
				discoverPrimaryNIC: func() string { return "eth0" },
				configureInterface: func(engine.EdgeInterfaceSpec) error { return nil },
				addRoute:           func(engine.EdgeRouteSpec) error { return nil },
				fetchIMDS: func(context.Context, string) (engine.CloudInitPayload, bool) {
					probed = true
					return engine.CloudInitPayload{
						Datasource: "imds-ec2",
						UserData:   "#cloud-config\naxonwall:\n  hub: wss://evil.example:2966/ws/satellite\n  token: ztp_evil\n  insecure_bootstrap: true\n",
					}, true
				},
				mergeCloudInit: engine.MergeCloudInitIntoBootConfig,
				setHostname:    func([]byte) error { return nil },
				nftConfPath:    filepath.Join(root, "etc", "nftables.conf"),
				rootDir:        root,
			}

			bootCfg := engine.ParseKernelCmdline(tc.cmdline)
			bootstrapPID1InterfacesAndIMDS(&bootCfg, tc.flagCore, tc.flagToken, deps)
			if probed != tc.wantProbe {
				t.Fatalf("probed = %v, want %v", probed, tc.wantProbe)
			}
			if tc.cmdline == "axonwall.hub=wss://hub.example:2966/ws/satellite axonwall.imds=1" {
				if bootCfg.HubURL != "wss://hub.example:2966/ws/satellite" {
					t.Fatalf("IMDS overwrote pre-populated HubURL: got %q", bootCfg.HubURL)
				}
				if bootCfg.InsecureBootstrap {
					t.Fatalf("IMDS enabled InsecureBootstrap")
				}
			}
		})
	}
}

func TestSecH05_PreExistingFirewallPolicyNotOverwrittenByIMDS(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	preExistingNft := "table inet axonwall {\n  chain input {\n    type filter hook input priority filter; policy drop;\n  }\n  chain forward {\n    type filter hook forward priority filter; policy drop;\n    comment \"pre-existing-policy\"\n  }\n}\n"
	nftConf := filepath.Join(etcDir, "nftables.conf")
	if err := os.WriteFile(nftConf, []byte(preExistingNft), 0o600); err != nil {
		t.Fatal(err)
	}

	var applied []string
	deps := pid1BootstrapDeps{
		applyNft: func(script string) error {
			applied = append(applied, script)
			return nil
		},
		confirmNft:         func() {},
		restoreFleet:       func() {},
		setForwarding:      func(bool) error { return nil },
		discoverPrimaryNIC: func() string { return "eth0" },
		configureInterface: func(engine.EdgeInterfaceSpec) error { return nil },
		addRoute:           func(engine.EdgeRouteSpec) error { return nil },
		fetchIMDS: func(context.Context, string) (engine.CloudInitPayload, bool) {
			return engine.CloudInitPayload{
				Datasource: "imds-openstack",
				UserData:   "#cloud-config\nwrite_files:\n  - path: /etc/nftables.conf\n    content: |\n      table inet axonwall {\n        chain forward {\n          type filter hook forward priority filter; policy accept;\n        }\n      }\n",
			}, true
		},
		mergeCloudInit: engine.MergeCloudInitIntoBootConfig,
		setHostname:    func([]byte) error { return nil },
		nftConfPath:    nftConf,
		rootDir:        root,
	}

	bootCfg := engine.ParseKernelCmdline("axonwall.imds=1")
	baselineScript, baselineApplied := applyPID1BaselineNft(defaultCoreURL, deps)
	bootstrapPID1InterfacesAndIMDS(&bootCfg, defaultCoreURL, "", deps)
	finalizePID1Nft(defaultCoreURL, baselineScript, baselineApplied, deps)

	if len(applied) != 1 || applied[0] != preExistingNft {
		t.Fatalf("expected pre-existing nftables policy to be applied once and preserved; got %d applies: %v", len(applied), applied)
	}
	gotOnDisk, err := os.ReadFile(nftConf)
	if err != nil || string(gotOnDisk) != preExistingNft {
		t.Fatalf("IMDS modified /etc/nftables.conf on disk: got %q (err=%v)", string(gotOnDisk), err)
	}
}

func TestSecL03_RunTailscaleUpUsesEphemeralAuthKeyFile(t *testing.T) {
	binDir := t.TempDir()
	recordDir := t.TempDir()
	argvLog := filepath.Join(recordDir, "argv.log")
	metaLog := filepath.Join(recordDir, "meta.log")

	// Fake tailscale binary that logs argv, verifies the authkey file exists with mode 0600,
	// records the file path and contents, and optionally exits non-zero.
	fakeTailscale := `#!/bin/sh
: > "$TS_ARGV_LOG"
for arg in "$@"; do
  printf '%s\n' "$arg" >> "$TS_ARGV_LOG"
  case "$arg" in
    --authkey=file:*)
      keyfile="${arg#--authkey=file:}"
      mode=$(stat -c '%a' "$keyfile" 2>/dev/null || echo unknown)
      content=$(cat "$keyfile" 2>/dev/null || echo "")
      printf 'path=%s\nmode=%s\ncontent=%s\n' "$keyfile" "$mode" "$content" > "$TS_META_LOG"
      ;;
  esac
done
exit "${TS_EXIT_CODE:-0}"
`
	if err := os.WriteFile(filepath.Join(binDir, "tailscale"), []byte(fakeTailscale), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("TS_ARGV_LOG", argvLog)
	t.Setenv("TS_META_LOG", metaLog)

	const secretKey = "tskey-auth-super-secret-value-xyz"

	runCheck := func(exitCode string) {
		t.Setenv("TS_EXIT_CODE", exitCode)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := runTailscaleUp(ctx, "https://headscale.example.com", secretKey)
		if exitCode == "0" && err != nil {
			t.Fatalf("runTailscaleUp unexpected error: %v", err)
		}
		if exitCode != "0" && err == nil {
			t.Fatalf("runTailscaleUp expected error when tailscale exits %s", exitCode)
		}

		argvBytes, err := os.ReadFile(argvLog)
		if err != nil {
			t.Fatalf("read argv log: %v", err)
		}
		argvText := string(argvBytes)
		if strings.Contains(argvText, secretKey) {
			t.Fatalf("secret authkey leaked in tailscale CLI argv: %q", argvText)
		}
		if !strings.Contains(argvText, "--authkey=file:") {
			t.Fatalf("expected --authkey=file:<path> in tailscale CLI argv, got: %q", argvText)
		}

		metaBytes, err := os.ReadFile(metaLog)
		if err != nil {
			t.Fatalf("read meta log: %v", err)
		}
		var keyPath, mode, content string
		for _, line := range strings.Split(strings.TrimSpace(string(metaBytes)), "\n") {
			if strings.HasPrefix(line, "path=") {
				keyPath = strings.TrimPrefix(line, "path=")
			} else if strings.HasPrefix(line, "mode=") {
				mode = strings.TrimPrefix(line, "mode=")
			} else if strings.HasPrefix(line, "content=") {
				content = strings.TrimPrefix(line, "content=")
			}
		}
		if keyPath == "" {
			t.Fatalf("missing temp key file path in meta log: %q", string(metaBytes))
		}
		if mode != "600" {
			t.Fatalf("expected temp authkey file mode 600, got %q", mode)
		}
		if content != secretKey {
			t.Fatalf("expected temp authkey file content %q, got %q", secretKey, content)
		}
		if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
			t.Fatalf("expected ephemeral authkey file %q to be removed immediately after tailscale up, stat err=%v", keyPath, statErr)
		}
	}

	t.Run("success unlinks temp authkey file", func(t *testing.T) {
		runCheck("0")
	})
	t.Run("failure still unlinks temp authkey file", func(t *testing.T) {
		runCheck("1")
	})
}
