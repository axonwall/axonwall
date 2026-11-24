package engine

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	defaultDocsDownloadBase = "https://github.com/axonwall/axonwall/releases/download"
	localDocsDropinPath     = "/var/lib/axonwall/downloads/axonwall-docs-latest.tar.gz"
)

var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?$`)

func (pm *PluginManager) docsPortalSiteDir() (string, error) {
	dir, err := pm.pluginDir("docs-portal")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "site"), nil
}

func (pm *PluginManager) isDocsBundleInstalled() bool {
	siteDir, err := pm.docsPortalSiteDir()
	if err != nil {
		return false
	}
	indexPath := filepath.Join(siteDir, "docs", "index.html")
	info, err := os.Lstat(indexPath)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func readRunningAxonwallVersion() string {
	candidates := []string{strings.TrimSpace(os.Getenv("AXONWALL_VERSION"))}
	if raw, err := os.ReadFile("/etc/axonwall/version"); err == nil {
		candidates = append(candidates, string(raw))
	}
	for _, cand := range candidates {
		ver := strings.TrimPrefix(strings.TrimSpace(cand), "v")
		if semverPattern.MatchString(ver) {
			return ver
		}
	}
	return ""
}

func (pm *PluginManager) collectReleaseSigningPubkeys() []string {
	if len(pm.releaseKeyPaths) > 0 {
		var out []string
		for _, p := range pm.releaseKeyPaths {
			if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
				out = append(out, p)
			}
		}
		return out
	}

	etcDir := strings.TrimSpace(os.Getenv("AXONWALL_ETC_DIR"))
	if etcDir == "" {
		etcDir = "/etc/axonwall"
	}
	var paths []string
	primary := filepath.Join(etcDir, "release-signing.pub")
	if info, err := os.Lstat(primary); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
		paths = append(paths, primary)
	}
	if matches, err := filepath.Glob(filepath.Join(etcDir, "release-signing.d", "*.pub")); err == nil {
		for _, m := range matches {
			if info, statErr := os.Lstat(m); statErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
				paths = append(paths, m)
			}
		}
	}
	return paths
}

func verifyDetachedReleaseSignature(messageBytes, sigBytes []byte, pubkeyPaths []string) error {
	if len(pubkeyPaths) == 0 {
		return fmt.Errorf("no release signing public keys configured")
	}
	if len(sigBytes) == 0 {
		return fmt.Errorf("detached release signature is empty")
	}
	digest := sha256.Sum256(messageBytes)
	var lastErr error
	for _, keyPath := range pubkeyPaths {
		rawPEM, err := os.ReadFile(keyPath)
		if err != nil {
			lastErr = err
			continue
		}
		block, _ := pem.Decode(rawPEM)
		if block == nil {
			lastErr = fmt.Errorf("%s: invalid PEM public key", keyPath)
			continue
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", keyPath, err)
			continue
		}
		switch pub := parsed.(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigBytes); err == nil {
				return nil
			} else {
				lastErr = err
			}
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
				return nil
			}
			lastErr = fmt.Errorf("%s: ecdsa signature mismatch", keyPath)
		default:
			lastErr = fmt.Errorf("%s: unsupported public key type %T", keyPath, parsed)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("signature verification failed")
	}
	return fmt.Errorf("release signature verification failed against %d keyring key(s): %w", len(pubkeyPaths), lastErr)
}

func parseSHA256FileBytes(data []byte) (string, error) {
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		hash := strings.TrimSpace(fields[0])
		if !sha256HexPattern.MatchString(hash) {
			return "", fmt.Errorf("invalid sha256 checksum token %q", hash)
		}
		return strings.ToLower(hash), nil
	}
	return "", fmt.Errorf("empty sha256 file")
}

func fetchSmallURL(rawURL string) ([]byte, int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("fetch %s: unexpected HTTP status %s", rawURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read %s: %w", rawURL, err)
	}
	return body, resp.StatusCode, nil
}

func (pm *PluginManager) buildDocsCandidateURLs(version string) []string {
	overrideBase := strings.TrimRight(strings.TrimSpace(pm.docsBundleBaseURL), "/")
	if overrideBase == "" {
		overrideBase = strings.TrimRight(strings.TrimSpace(os.Getenv("AXONWALL_DOCS_BASE_URL")), "/")
	}
	if overrideBase != "" {
		var urls []string
		if version != "" {
			urls = append(urls, fmt.Sprintf("%s/axonwall-docs-%s.tar.gz", overrideBase, version))
		}
		urls = append(urls, fmt.Sprintf("%s/axonwall-docs-latest.tar.gz", overrideBase))
		return urls
	}
	var urls []string
	if version != "" {
		urls = append(urls, fmt.Sprintf("%s/v%s/axonwall-docs-%s.tar.gz", defaultDocsDownloadBase, version, version))
	}
	urls = append(urls, fmt.Sprintf("%s/rolling-latest/axonwall-docs-latest.tar.gz", defaultDocsDownloadBase))
	return urls
}

func (pm *PluginManager) acquireVerifiedDocsArchive(tmpDir string, logOut *strings.Builder) (string, string, error) {
	pubkeys := pm.collectReleaseSigningPubkeys()

	// Path A: Explicit local bundle override, offline plugin-cache, or air-gapped drop-in file.
	explicitPath := strings.TrimSpace(os.Getenv("AXONWALL_DOCS_BUNDLE_PATH"))
	localPath := explicitPath
	requiredLocalSHA := explicitPath != "" && strings.TrimSpace(os.Getenv("AXONWALL_DOCS_ALLOW_UNVERIFIED_LOCAL")) != "1"
	if localPath == "" {
		cacheDocsPath := filepath.Join(pluginCacheDir(), "docs-portal", "axonwall-docs-latest.tar.gz")
		if info, err := os.Stat(cacheDocsPath); err == nil && info.Mode().IsRegular() {
			localPath = cacheDocsPath
			requiredLocalSHA = true
		} else if info, err := os.Stat(localDocsDropinPath); err == nil && info.Mode().IsRegular() {
			localPath = localDocsDropinPath
			requiredLocalSHA = true
		}
	}
	if localPath != "" {
		actualHash, err := sha256File(localPath)
		if err != nil {
			return "", "", fmt.Errorf("local docs bundle %s: %w", localPath, err)
		}
		wantHash := strings.ToLower(strings.TrimSpace(os.Getenv("AXONWALL_DOCS_BUNDLE_SHA256")))
		var shaBytes []byte
		if wantHash != "" {
			if !sha256HexPattern.MatchString(wantHash) {
				return "", "", fmt.Errorf("AXONWALL_DOCS_BUNDLE_SHA256 is not a valid 64-hex sha256 digest")
			}
		} else {
			shaFile := localPath + ".sha256"
			data, readErr := os.ReadFile(shaFile)
			if readErr == nil {
				shaBytes = data
				wantHash, err = parseSHA256FileBytes(data)
				if err != nil {
					return "", "", fmt.Errorf("parse %s: %w", shaFile, err)
				}
			} else if requiredLocalSHA {
				return "", "", fmt.Errorf("missing required checksum file %s alongside %s", shaFile, localPath)
			}
		}
		if wantHash != "" && actualHash != wantHash {
			return "", "", fmt.Errorf("local docs bundle sha256 mismatch: got %s, want %s", actualHash, wantHash)
		}
		if sigBytes, sigErr := os.ReadFile(localPath + ".sha256.sig"); sigErr == nil && len(pubkeys) > 0 && len(shaBytes) > 0 {
			if err := verifyDetachedReleaseSignature(shaBytes, sigBytes, pubkeys); err != nil {
				return "", "", err
			}
		}
		fmt.Fprintf(logOut, "Using local docs bundle %s (sha256=%s)\n", localPath, actualHash)
		return localPath, actualHash, nil
	}

	// Path B: Download from configured base URL or official GitHub Releases.
	version := readRunningAxonwallVersion()
	candidates := pm.buildDocsCandidateURLs(version)
	var notFoundErrs []string

	for _, tarURL := range candidates {
		shaURL := tarURL + ".sha256"
		shaBytes, status, err := fetchSmallURL(shaURL)
		if err != nil {
			if status == http.StatusNotFound {
				notFoundErrs = append(notFoundErrs, fmt.Sprintf("%s (HTTP 404)", shaURL))
				continue
			}
			return "", "", fmt.Errorf("could not fetch docs bundle checksum: %w", err)
		}
		wantSHA, err := parseSHA256FileBytes(shaBytes)
		if err != nil {
			return "", "", fmt.Errorf("invalid checksum at %s: %w", shaURL, err)
		}
		if len(pubkeys) > 0 {
			sigURL := shaURL + ".sig"
			sigBytes, _, sigErr := fetchSmallURL(sigURL)
			if sigErr != nil {
				return "", "", fmt.Errorf("release signing key configured but signature %s unavailable: %w", sigURL, sigErr)
			}
			if err := verifyDetachedReleaseSignature(shaBytes, sigBytes, pubkeys); err != nil {
				return "", "", err
			}
			fmt.Fprintf(logOut, "Verified detached release signature for %s\n", shaURL)
		}
		archivePath, err := downloadVerified(tarURL, wantSHA, tmpDir)
		if err != nil {
			return "", "", err
		}
		fmt.Fprintf(logOut, "Downloaded and SHA-256 verified %s (sha256=%s)\n", tarURL, wantSHA)
		return archivePath, wantSHA, nil
	}

	return "", "", fmt.Errorf("no downloadable docs bundle found (tried: %s)", strings.Join(notFoundErrs, ", "))
}

func (pm *PluginManager) installDocsPortal() PluginActionResponse {
	docsDir, err := pm.pluginDir("docs-portal")
	if err != nil {
		return PluginActionResponse{Success: false, Message: err.Error()}
	}
	if err := os.MkdirAll(docsDir, 0755); err != nil {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to create docs-portal directory: %v", err),
		}
	}

	tmpDir, err := os.MkdirTemp("", "axonwall-docs-install-*")
	if err != nil {
		return PluginActionResponse{Success: false, Message: fmt.Sprintf("Failed to allocate temp dir: %v", err)}
	}
	defer os.RemoveAll(tmpDir)

	var out strings.Builder
	archivePath, wantSHA, err := pm.acquireVerifiedDocsArchive(tmpDir, &out)
	if err != nil {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to obtain verified Offline Documentation Portal bundle: %v", err),
			Output:  out.String(),
		}
	}

	stageDir, err := os.MkdirTemp(docsDir, "site.staging-*")
	if err != nil {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to create staging directory: %v", err),
			Output:  out.String(),
		}
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = os.RemoveAll(stageDir)
		}
	}()

	if err := extractArchiveTree(archivePath, "tar.gz", 0, stageDir); err != nil {
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to extract Offline Documentation Portal archive: %v", err),
			Output:  out.String(),
		}
	}

	indexInfo, err := os.Lstat(filepath.Join(stageDir, "docs", "index.html"))
	if err != nil || !indexInfo.Mode().IsRegular() {
		return PluginActionResponse{
			Success: false,
			Message: "Extracted docs archive is missing required docs/index.html entrypoint.",
			Output:  out.String(),
		}
	}

	// Ensure unprivileged axonwall-ui user (User=axonwall) can read extracted files.
	_ = filepath.WalkDir(stageDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return os.Chmod(path, 0755)
		}
		return os.Chmod(path, 0644)
	})

	siteDir := filepath.Join(docsDir, "site")
	prevDir := filepath.Join(docsDir, "site.prev")
	_ = os.RemoveAll(prevDir)
	if _, statErr := os.Lstat(siteDir); statErr == nil {
		if err := os.Rename(siteDir, prevDir); err != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to rotate previous docs site dir: %v", err),
				Output:  out.String(),
			}
		}
	}
	if err := os.Rename(stageDir, siteDir); err != nil {
		_ = os.Rename(prevDir, siteDir)
		return PluginActionResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to promote docs site dir: %v", err),
			Output:  out.String(),
		}
	}
	cleanupStage = false
	_ = os.RemoveAll(prevDir)

	pm.mu.Lock()
	delete(pm.disabledMap, "docs-portal")
	pm.installedMap["docs-portal"] = time.Now().UTC().Format(time.RFC3339)
	pm.saveState()
	pm.mu.Unlock()

	fmt.Fprintf(&out, "Installed offline docs bundle into %s (sha256=%s)\n", siteDir, wantSHA)
	return PluginActionResponse{
		Success: true,
		Message: "Installed Offline Documentation Portal (docs-portal) and enabled offline documentation serving.",
		Output:  out.String(),
	}
}

func (pm *PluginManager) uninstallDocsPortal() PluginActionResponse {
	dir, err := pm.pluginDir("docs-portal")
	if err != nil {
		return PluginActionResponse{Success: false, Message: err.Error()}
	}
	if info, statErr := os.Lstat(dir); statErr == nil {
		var rmErr error
		if info.Mode()&os.ModeSymlink != 0 {
			rmErr = os.Remove(dir)
		} else {
			rmErr = os.RemoveAll(dir)
		}
		if rmErr != nil {
			return PluginActionResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to remove docs-portal storage %s: %v", dir, rmErr),
			}
		}
	}

	pm.mu.Lock()
	delete(pm.installedMap, "docs-portal")
	pm.disabledMap["docs-portal"] = true
	pm.saveState()
	pm.mu.Unlock()

	return PluginActionResponse{
		Success: true,
		Message: "Uninstalled Offline Documentation Portal and freed local bundle storage (online docs remain available at https://axonwall.com/docs).",
	}
}
