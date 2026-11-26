package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

type K3sAppPodStatus struct {
	Name   string `json:"name"`
	Phase  string `json:"phase"`
	Ready  bool   `json:"ready"`
	Image  string `json:"image,omitempty"`
	Node   string `json:"node,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func isDisallowedPluginAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	return addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified()
}

func isDisallowedPluginIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return isDisallowedPluginAddr(addr)
}

func newInternalK3sHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				h, p, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, h)
				if lookupErr != nil || len(ips) == 0 {
					return nil, fmt.Errorf("failed to resolve plugin endpoint host %s: %v", h, lookupErr)
				}
				for _, ipAddr := range ips {
					if isDisallowedPluginIP(ipAddr.IP) {
						return nil, fmt.Errorf("disallowed link-local/IMDS/multicast target IP %s for %s", ipAddr.IP.String(), h)
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), p))
			},
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// Internal K3s Ingress services (NetBox / LibreNMS) frequently serve self-signed Traefik certificates
				InsecureSkipVerify: true, // #nosec G402 -- local/K3s internal TLS option
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("outbound HTTP redirects are disallowed for plugin API requests")
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
	if u.User != nil {
		return "", fmt.Errorf("invalid %s endpoint URL: embedded credentials are disallowed", pluginLabel)
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u.Hostname())), ".")
	if u.Host == "" || host == "" {
		return "", fmt.Errorf("invalid %s endpoint URL: missing host", pluginLabel)
	}
	switch host {
	case "metadata.google.internal", "metadata.goog", "metadata", "instance-data", "fd00:ec2::254":
		return "", fmt.Errorf("disallowed %s metadata endpoint host %q", pluginLabel, u.Hostname())
	}
	if addr, aerr := netip.ParseAddr(host); aerr == nil && isDisallowedPluginAddr(addr) {
		return "", fmt.Errorf("disallowed %s link-local/IMDS/multicast address %q", pluginLabel, u.Hostname())
	}
	return strings.TrimRight(trimmed, "/"), nil
}

func normalizedURLOrigin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u.Hostname())), ".")
	if host == "" {
		return "", false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port), true
}

func tokenIfSameOrigin(overrideURL string, configuredBases []string, token string) string {
	if token == "" || strings.TrimSpace(overrideURL) == "" {
		return token
	}
	overrideOrigin, ok := normalizedURLOrigin(overrideURL)
	if !ok {
		return ""
	}
	for _, base := range configuredBases {
		if strings.TrimSpace(base) == "" {
			continue
		}
		if baseOrigin, bok := normalizedURLOrigin(base); bok && baseOrigin == overrideOrigin {
			return token
		}
	}
	return ""
}

func sanitizeHTTPErrorBody(body []byte, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 256
	}
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(min(len(raw), maxLen))
	lastSpace := false
	for _, r := range raw {
		if b.Len() >= maxLen {
			b.WriteString("...")
			break
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		b.WriteRune(r)
		lastSpace = false
	}
	return strings.TrimSpace(b.String())
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
