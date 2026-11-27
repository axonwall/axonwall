package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// SafeHTTPClientOptions configures the shared SSRF-hardened HTTP client/transport.
type SafeHTTPClientOptions struct {
	Timeout         time.Duration
	DialTimeout     time.Duration
	AllowLoopback   bool
	BlockPrivate    bool
	TLSClientConfig *tls.Config
	MaxIdleConns    int
	IdleConnTimeout time.Duration
}

var (
	safeHTTPBlockedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),    // IPv4 link-local / IMDS
		netip.MustParsePrefix("0.0.0.0/8"),         // "This" network (RFC 1122)
		netip.MustParsePrefix("fe80::/10"),         // IPv6 link-local
		netip.MustParsePrefix("100::/64"),          // IPv6 discard-only (RFC 6666)
		netip.MustParsePrefix("2001:db8::/32"),     // IPv6 documentation (RFC 3849)
		netip.MustParsePrefix("2002::/16"),         // 6to4 (RFC 3056)
		netip.MustParsePrefix("2001::/32"),         // Teredo (RFC 4380)
		netip.MustParsePrefix("64:ff9b:1::/48"),    // IPv4/IPv6 local-use translation (RFC 8215)
		netip.MustParsePrefix("fec0::/10"),         // Deprecated IPv6 site-local (RFC 3879)
		netip.MustParsePrefix("fd00:ec2::254/128"), // AWS IPv6 IMDS
	}
	safeHTTPIPv4MappedPrefix = netip.MustParsePrefix("::ffff:0:0/96")
)

func isBlockedSafeHTTPHostname(host string, allowLoopback bool) (bool, string) {
	norm := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if norm == "" {
		return true, "empty hostname"
	}
	if !allowLoopback && (norm == "localhost" || strings.HasSuffix(norm, ".localhost")) {
		return true, "loopback hostname"
	}
	switch norm {
	case "metadata.google.internal", "metadata.goog", "metadata", "instance-data", "metadata.azure.internal":
		return true, "cloud metadata hostname"
	}
	return false, ""
}

func isBlockedSafeHTTPAddr(addr netip.Addr, allowLoopback, blockPrivate bool) (bool, string) {
	if !addr.IsValid() {
		return true, "invalid IP"
	}
	// Explicitly block IPv4-mapped IPv6 addresses (::ffff:0:0:0/96).
	if addr.Is4In6() || safeHTTPIPv4MappedPrefix.Contains(addr) {
		return true, "::ffff:0:0/96 IPv4-mapped IPv6 is disallowed"
	}
	if addr.IsUnspecified() {
		return true, "unspecified address"
	}
	if addr.IsMulticast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() {
		return true, "multicast address"
	}
	if addr.IsLinkLocalUnicast() {
		return true, "link-local address"
	}
	if !allowLoopback && addr.IsLoopback() {
		return true, "loopback address"
	}
	if blockPrivate && addr.IsPrivate() {
		return true, "private address"
	}
	for _, pfx := range safeHTTPBlockedPrefixes {
		if pfx.Contains(addr) {
			return true, fmt.Sprintf("blocked CIDR %s", pfx.String())
		}
	}
	return false, ""
}

func netIPToSafeAddr(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFromSlice(ip4)
	}
	return netip.AddrFromSlice(ip)
}

func newSafeHTTPTransport(opts SafeHTTPClientOptions) *http.Transport {
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = opts.Timeout
	}
	if dialTimeout <= 0 || dialTimeout > 10*time.Second {
		dialTimeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: dialTimeout}

	tlsCfg := opts.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tr := &http.Transport{
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: true,
		MaxIdleConns:      opts.MaxIdleConns,
		IdleConnTimeout:   opts.IdleConnTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid target address %q: %w", addr, err)
			}
			if blocked, reason := isBlockedSafeHTTPHostname(h, opts.AllowLoopback); blocked {
				return nil, fmt.Errorf("disallowed outbound target host %q (%s)", h, reason)
			}
			// Catch literal IPv4-mapped IPv6 addresses (e.g. [::ffff:127.0.0.1]) before DNS/To4 normalization.
			if lit, parseErr := netip.ParseAddr(strings.Trim(h, "[]")); parseErr == nil {
				if blocked, reason := isBlockedSafeHTTPAddr(lit, opts.AllowLoopback, opts.BlockPrivate); blocked {
					return nil, fmt.Errorf("disallowed outbound target IP %s (%s)", lit.String(), reason)
				}
			}

			ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, h)
			if lookupErr != nil || len(ips) == 0 {
				return nil, fmt.Errorf("failed to resolve outbound host %q: %v", h, lookupErr)
			}
			validated := make([]string, 0, len(ips))
			for _, ipAddr := range ips {
				parsed, ok := netIPToSafeAddr(ipAddr.IP)
				if !ok {
					return nil, fmt.Errorf("disallowed resolved IP %q for host %q", ipAddr.IP.String(), h)
				}
				if blocked, reason := isBlockedSafeHTTPAddr(parsed, opts.AllowLoopback, opts.BlockPrivate); blocked {
					return nil, fmt.Errorf("disallowed resolved IP %s for host %q (%s)", parsed.String(), h, reason)
				}
				validated = append(validated, parsed.String())
			}

			var lastErr error
			for _, targetIP := range validated {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(targetIP, p))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	return tr
}

func newSafeHTTPClient(opts SafeHTTPClientOptions) (*http.Client, *http.Transport) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := newSafeHTTPTransport(opts)
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, tr
}
