package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type K3sAppPodStatus struct {
	Name   string `json:"name"`
	Phase  string `json:"phase"`
	Ready  bool   `json:"ready"`
	Image  string `json:"image,omitempty"`
	Node   string `json:"node,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func newInternalK3sHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// Internal K3s Ingress services (NetBox / LibreNMS) frequently serve self-signed Traefik certificates
				InsecureSkipVerify: true, // #nosec G402 -- local/K3s internal TLS option
			},
		},
	}
}

func runPluginKubectl(ctx context.Context, runner func(ctx context.Context, args ...string) ([]byte, error), args ...string) ([]byte, error) {
	if runner != nil {
		return runner(ctx, args...)
	}
	if k3sBin, err := resolveK3sBinary(); err == nil {
		fullArgs := append([]string{"kubectl"}, args...)
		return exec.CommandContext(ctx, k3sBin, fullArgs...).CombinedOutput()
	}
	return exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
}

func validatePluginHTTPURL(raw, pluginLabel string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%s endpoint URL is empty", pluginLabel)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid %s endpoint URL: %w", pluginLabel, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported %s endpoint scheme %q: must be http or https", pluginLabel, u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid %s endpoint URL: missing host", pluginLabel)
	}
	return strings.TrimRight(trimmed, "/"), nil
}

func readPluginLDAPBindPasswordFromFile(pathOverride, pluginSlug string) string {
	path := strings.TrimSpace(pathOverride)
	if path == "" {
		path = filepath.Join(LDAPPluginClientsDir, pluginSlug+".json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var binding PluginLDAPBinding
	if err := json.Unmarshal(raw, &binding); err != nil {
		return ""
	}
	return binding.BindPassword
}

func inspectK3sAppPodsAndService(
	ctx context.Context,
	runner func(ctx context.Context, args ...string) ([]byte, error),
	namespace, serviceName string,
) ([]K3sAppPodStatus, string) {
	pods := []K3sAppPodStatus{}
	var clusterIP string

	if out, err := runPluginKubectl(ctx, runner, "-n", namespace, "get", "pods", "-o", "json"); err == nil {
		var podList struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Spec struct {
					NodeName   string `json:"nodeName"`
					Containers []struct {
						Image string `json:"image"`
					} `json:"containers"`
				} `json:"spec"`
				Status struct {
					Phase             string `json:"phase"`
					Reason            string `json:"reason"`
					ContainerStatuses []struct {
						Ready bool `json:"ready"`
					} `json:"containerStatuses"`
				} `json:"status"`
			} `json:"items"`
		}
		if json.Unmarshal(out, &podList) == nil {
			for _, p := range podList.Items {
				ready := len(p.Status.ContainerStatuses) > 0
				for _, cs := range p.Status.ContainerStatuses {
					if !cs.Ready {
						ready = false
						break
					}
				}
				img := ""
				if len(p.Spec.Containers) > 0 {
					img = p.Spec.Containers[0].Image
				}
				pods = append(pods, K3sAppPodStatus{
					Name:   p.Metadata.Name,
					Phase:  p.Status.Phase,
					Ready:  ready,
					Image:  img,
					Node:   p.Spec.NodeName,
					Reason: p.Status.Reason,
				})
			}
		}
	}

	if out, err := runPluginKubectl(ctx, runner, "-n", namespace, "get", "service", serviceName, "-o", "json"); err == nil {
		var svc struct {
			Spec struct {
				ClusterIP string `json:"clusterIP"`
			} `json:"spec"`
		}
		if json.Unmarshal(out, &svc) == nil {
			ip := strings.TrimSpace(svc.Spec.ClusterIP)
			if ip != "" && ip != "None" {
				clusterIP = ip
			}
		}
	}

	return pods, clusterIP
}

func randomHexToken(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
