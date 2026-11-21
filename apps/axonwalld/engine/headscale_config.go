package engine

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var validMagicDNSDomainRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)

func validateHeadscaleServerURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if strings.ContainsAny(trimmed, " \t\r\n\x00\"'") {
		return "", fmt.Errorf("invalid serverUrl: whitespace, control characters, and quotes are not allowed")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid serverUrl: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("invalid serverUrl scheme %q: must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid serverUrl: host is required")
	}
	return strings.TrimRight(trimmed, "/"), nil
}

func validateHeadscaleMagicDNSDomain(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if strings.ContainsAny(trimmed, " \t\r\n\x00\"'") || strings.Contains(trimmed, "..") || strings.HasSuffix(trimmed, ".") || strings.HasSuffix(trimmed, "-") {
		return "", fmt.Errorf("invalid magicDnsDomain: %q", raw)
	}
	if !validMagicDNSDomainRe.MatchString(trimmed) {
		return "", fmt.Errorf("invalid magicDnsDomain: must be a valid DNS domain name")
	}
	return trimmed, nil
}

// SyncHeadscaleConfig non-destructively updates server_url and dns.base_domain
// inside /etc/headscale/config.yaml while preserving comments, DERP settings,
// SQLite paths, TLS config, and unix socket configuration.
func SyncHeadscaleConfig(configPath, serverUrl, magicDnsDomain string) (bool, error) {
	cleanURL, err := validateHeadscaleServerURL(serverUrl)
	if err != nil {
		return false, err
	}
	cleanDomain, err := validateHeadscaleMagicDNSDomain(magicDnsDomain)
	if err != nil {
		return false, err
	}
	if cleanURL == "" && cleanDomain == "" {
		return false, nil
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return false, fmt.Errorf("failed to read %s: %w", configPath, err)
	}
	origContent := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(origContent, "\n")

	inDns := false
	serverUrlUpdated := false
	dnsBaseUpdated := false
	dnsHeaderIdx := -1
	outLines := make([]string, 0, len(lines)+4)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		isIndented := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		if !isIndented && trimmed != "" && !strings.HasPrefix(trimmed, "#") && trimmed != "---" {
			inDns = trimmed == "dns:" || strings.HasPrefix(trimmed, "dns:")
		}

		if cleanURL != "" && !isIndented && strings.HasPrefix(trimmed, "server_url:") {
			outLines = append(outLines, "server_url: "+cleanURL)
			serverUrlUpdated = true
			continue
		}

		if cleanDomain != "" && !isIndented && (trimmed == "dns:" || strings.HasPrefix(trimmed, "dns:")) {
			dnsHeaderIdx = len(outLines)
			outLines = append(outLines, line)
			inDns = true
			continue
		}

		if cleanDomain != "" && inDns && isIndented && strings.HasPrefix(trimmed, "base_domain:") {
			indentLen := len(line) - len(strings.TrimLeft(line, " \t"))
			indent := line[:indentLen]
			outLines = append(outLines, indent+"base_domain: "+cleanDomain)
			dnsBaseUpdated = true
			continue
		}

		outLines = append(outLines, line)
	}

	if cleanURL != "" && !serverUrlUpdated {
		insertAt := 0
		if len(outLines) > 0 && strings.TrimSpace(outLines[0]) == "---" {
			insertAt = 1
		}
		updated := make([]string, 0, len(outLines)+1)
		updated = append(updated, outLines[:insertAt]...)
		updated = append(updated, "server_url: "+cleanURL)
		updated = append(updated, outLines[insertAt:]...)
		outLines = updated
		if dnsHeaderIdx >= insertAt {
			dnsHeaderIdx++
		}
	}

	if cleanDomain != "" && !dnsBaseUpdated {
		if dnsHeaderIdx >= 0 {
			updated := make([]string, 0, len(outLines)+1)
			updated = append(updated, outLines[:dnsHeaderIdx+1]...)
			updated = append(updated, "  base_domain: "+cleanDomain)
			updated = append(updated, outLines[dnsHeaderIdx+1:]...)
			outLines = updated
		} else {
			if len(outLines) > 0 && outLines[len(outLines)-1] != "" {
				outLines = append(outLines, "dns:", "  magic_dns: true", "  base_domain: "+cleanDomain)
			} else if len(outLines) > 0 {
				outLines[len(outLines)-1] = "dns:"
				outLines = append(outLines, "  magic_dns: true", "  base_domain: "+cleanDomain, "")
			} else {
				outLines = append(outLines, "dns:", "  magic_dns: true", "  base_domain: "+cleanDomain)
			}
		}
	}

	newContent := strings.Join(outLines, "\n")
	if newContent == origContent {
		return false, nil
	}

	dir := filepath.Dir(configPath)
	tmpFile, err := os.CreateTemp(dir, ".headscale-config-*")
	if err != nil {
		return false, fmt.Errorf("failed to stage %s: %w", configPath, err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.WriteString(newContent); err != nil {
		_ = tmpFile.Close()
		return false, fmt.Errorf("failed to write staged config %s: %w", configPath, err)
	}
	if err := tmpFile.Close(); err != nil {
		return false, fmt.Errorf("failed to close staged config %s: %w", configPath, err)
	}
	if err := os.Chmod(tmpPath, 0640); err != nil {
		return false, fmt.Errorf("failed to chmod staged config %s: %w", configPath, err)
	}
	if os.Geteuid() == 0 {
		_ = exec.Command("chown", "root:axonwall-api", tmpPath).Run()
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		return false, fmt.Errorf("failed to install %s: %w", configPath, err)
	}
	cleanupTmp = false
	return true, nil
}
