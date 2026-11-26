package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var mmdbMetadataMarker = []byte("\xab\xcd\xefMaxMind.com")

// MMDBMetadata holds parsed MaxMind DB header fields.
type MMDBMetadata struct {
	NodeCount    uint64
	RecordSize   uint16
	IPVersion    uint16
	DatabaseType string
	BuildEpoch   uint64
}

// MMDBReader implements a zero-dependency pure-Go MaxMind DB v2 reader.
type MMDBReader struct {
	data          []byte
	meta          MMDBMetadata
	nodeByteSize  int
	searchTreeEnd int
	dataStart     int
	ipv4StartNode uint64
}

// OpenMMDBFile loads an .mmdb database file into memory for lock-free lookups.
func OpenMMDBFile(path string) (*MMDBReader, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return OpenMMDBBytes(raw)
}

// OpenMMDBBytes parses an in-memory .mmdb payload.
func OpenMMDBBytes(raw []byte) (*MMDBReader, error) {
	if len(raw) < len(mmdbMetadataMarker)+4 {
		return nil, errors.New("mmdb buffer too small")
	}
	searchStart := 0
	if len(raw) > 128*1024 {
		searchStart = len(raw) - 128*1024
	}
	idx := bytes.LastIndex(raw[searchStart:], mmdbMetadataMarker)
	if idx < 0 {
		return nil, errors.New("missing MaxMind.com metadata marker")
	}
	metaOff := searchStart + idx + len(mmdbMetadataMarker)
	r := &MMDBReader{data: raw}
	metaVal, _, err := r.decodeValue(metaOff, metaOff, 0)
	if err != nil {
		return nil, fmt.Errorf("decoding mmdb metadata: %w", err)
	}
	metaMap, ok := metaVal.(map[string]any)
	if !ok {
		return nil, errors.New("mmdb metadata is not a map")
	}

	r.meta.NodeCount = asUint64Any(metaMap["node_count"])
	r.meta.RecordSize = uint16(asUint64Any(metaMap["record_size"]))
	r.meta.IPVersion = uint16(asUint64Any(metaMap["ip_version"]))
	r.meta.BuildEpoch = asUint64Any(metaMap["build_epoch"])
	if s, ok := metaMap["database_type"].(string); ok {
		r.meta.DatabaseType = s
	}

	if r.meta.RecordSize != 24 && r.meta.RecordSize != 28 && r.meta.RecordSize != 32 {
		return nil, fmt.Errorf("unsupported mmdb record_size %d", r.meta.RecordSize)
	}
	if len(raw) < 16 {
		return nil, errors.New("mmdb search tree exceeds file length")
	}
	r.nodeByteSize = int(r.meta.RecordSize) / 4
	nodeBytes := uint64(r.nodeByteSize)
	if nodeBytes == 0 || r.meta.NodeCount > uint64(len(raw)-16)/nodeBytes {
		return nil, errors.New("mmdb search tree exceeds file length")
	}
	r.searchTreeEnd = int(r.meta.NodeCount * nodeBytes)
	r.dataStart = r.searchTreeEnd + 16
	if r.dataStart > len(raw) {
		return nil, errors.New("mmdb search tree exceeds file length")
	}

	// Precompute IPv4 start node (96 zero-bits in an IPv6 tree).
	if r.meta.IPVersion == 6 {
		node := uint64(0)
		for i := 0; i < 96 && node < r.meta.NodeCount; i++ {
			node = r.readNode(node, 0)
		}
		r.ipv4StartNode = node
	}
	return r, nil
}

func (r *MMDBReader) readNode(node uint64, bit uint8) uint64 {
	off := int(node) * r.nodeByteSize
	if off+r.nodeByteSize > r.searchTreeEnd {
		return r.meta.NodeCount
	}
	b := r.data[off : off+r.nodeByteSize]
	switch r.meta.RecordSize {
	case 24:
		if bit == 0 {
			return uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
		}
		return uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
	case 28:
		if bit == 0 {
			return (uint64(b[3]&0xF0) << 20) | uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
		}
		return (uint64(b[3]&0x0F) << 24) | uint64(b[4])<<16 | uint64(b[5])<<8 | uint64(b[6])
	case 32:
		if bit == 0 {
			return uint64(binary.BigEndian.Uint32(b[0:4]))
		}
		return uint64(binary.BigEndian.Uint32(b[4:8]))
	default:
		return r.meta.NodeCount
	}
}

// Lookup resolves an IPv4 or IPv6 address to its decoded MMDB map.
func (r *MMDBReader) Lookup(addr netip.Addr) (map[string]any, bool) {
	if r == nil || !addr.IsValid() || r.meta.NodeCount == 0 {
		return nil, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() {
		return nil, false
	}
	var ipBytes []byte
	var node uint64
	if addr.Is4() {
		a4 := addr.As4()
		ipBytes = a4[:]
		if r.meta.IPVersion == 6 {
			node = r.ipv4StartNode
		}
	} else {
		if r.meta.IPVersion != 6 {
			return nil, false
		}
		a16 := addr.As16()
		ipBytes = a16[:]
	}

	bitLen := len(ipBytes) * 8
	for bitIdx := 0; bitIdx < bitLen; bitIdx++ {
		if node >= r.meta.NodeCount {
			break
		}
		bit := (ipBytes[bitIdx>>3] >> uint(7-(bitIdx&7))) & 1
		node = r.readNode(node, bit)
	}

	if node == r.meta.NodeCount || node < r.meta.NodeCount {
		return nil, false
	}
	offset := int(node-r.meta.NodeCount) + r.searchTreeEnd
	if offset < r.dataStart || offset >= len(r.data) {
		return nil, false
	}
	val, _, err := r.decodeValue(offset, r.dataStart, 0)
	if err != nil {
		return nil, false
	}
	m, ok := val.(map[string]any)
	return m, ok
}

// LookupCity extracts country ISO, English city name, and coordinates.
func (r *MMDBReader) LookupCity(addr netip.Addr) (countryISO, cityName string, lat, lon float64, ok bool) {
	rec, found := r.Lookup(addr)
	if !found {
		return "", "", 0, 0, false
	}
	if countryMap, okC := rec["country"].(map[string]any); okC {
		if iso, okI := countryMap["iso_code"].(string); okI {
			countryISO = iso
		}
	} else if regMap, okR := rec["registered_country"].(map[string]any); okR {
		if iso, okI := regMap["iso_code"].(string); okI {
			countryISO = iso
		}
	}
	if cityMap, okCt := rec["city"].(map[string]any); okCt {
		if namesMap, okN := cityMap["names"].(map[string]any); okN {
			if en, okE := namesMap["en"].(string); okE {
				cityName = en
			} else {
				for _, v := range namesMap {
					if s, okS := v.(string); okS && s != "" {
						cityName = s
						break
					}
				}
			}
		}
	}
	if locMap, okL := rec["location"].(map[string]any); okL {
		lat = asFloat64Any(locMap["latitude"])
		lon = asFloat64Any(locMap["longitude"])
	}
	return countryISO, cityName, lat, lon, countryISO != "" || cityName != ""
}

// LookupASN extracts Autonomous System Number and Organization.
func (r *MMDBReader) LookupASN(addr netip.Addr) (asn uint32, org string, ok bool) {
	rec, found := r.Lookup(addr)
	if !found {
		return 0, "", false
	}
	asn = uint32(asUint64Any(rec["autonomous_system_number"]))
	if s, okO := rec["autonomous_system_organization"].(string); okO {
		org = s
	}
	return asn, org, asn > 0 || org != ""
}

func (r *MMDBReader) decodeValue(off, baseDataStart, depth int) (any, int, error) {
	if depth > 32 || off < 0 || off >= len(r.data) {
		return nil, off, errors.New("mmdb decode out of bounds or max depth")
	}
	ctrl := r.data[off]
	off++
	t := int(ctrl >> 5)
	if t == 0 {
		if off >= len(r.data) {
			return nil, off, errors.New("mmdb truncated extended type")
		}
		t = int(r.data[off]) + 7
		off++
	}
	if t == 1 { // pointer
		ptrSize := (ctrl >> 3) & 0x03
		if off+int(ptrSize)+1 > len(r.data) {
			return nil, off, errors.New("mmdb truncated pointer")
		}
		var ptr uint32
		packed := uint32(ctrl & 0x07)
		switch ptrSize {
		case 0:
			ptr = (packed << 8) | uint32(r.data[off])
			off++
		case 1:
			ptr = ((packed << 16) | (uint32(r.data[off]) << 8) | uint32(r.data[off+1])) + 2048
			off += 2
		case 2:
			ptr = ((packed << 24) | (uint32(r.data[off]) << 16) | (uint32(r.data[off+1]) << 8) | uint32(r.data[off+2])) + 526336
			off += 3
		case 3:
			ptr = binary.BigEndian.Uint32(r.data[off : off+4])
			off += 4
		}
		target := baseDataStart + int(ptr)
		val, _, err := r.decodeValue(target, baseDataStart, depth+1)
		return val, off, err
	}

	payload := int(ctrl & 0x1F)
	switch payload {
	case 29:
		if off >= len(r.data) {
			return nil, off, errors.New("mmdb truncated size29")
		}
		payload = 29 + int(r.data[off])
		off++
	case 30:
		if off+2 > len(r.data) {
			return nil, off, errors.New("mmdb truncated size30")
		}
		payload = 285 + int(binary.BigEndian.Uint16(r.data[off:off+2]))
		off += 2
	case 31:
		if off+3 > len(r.data) {
			return nil, off, errors.New("mmdb truncated size31")
		}
		payload = 65821 + (int(r.data[off])<<16 | int(r.data[off+1])<<8 | int(r.data[off+2]))
		off += 3
	}

	switch t {
	case 2: // utf8_string
		if off+payload > len(r.data) {
			return nil, off, errors.New("mmdb truncated utf8 string")
		}
		s := string(r.data[off : off+payload])
		return s, off + payload, nil
	case 3: // double
		if off+8 > len(r.data) {
			return nil, off, errors.New("mmdb truncated double")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(r.data[off : off+8])), off + 8, nil
	case 4: // bytes
		if off+payload > len(r.data) {
			return nil, off, errors.New("mmdb truncated bytes")
		}
		b := make([]byte, payload)
		copy(b, r.data[off:off+payload])
		return b, off + payload, nil
	case 5, 6, 9, 10: // uint16, uint32, uint64, uint128
		if payload > 16 || off+payload > len(r.data) {
			return nil, off, errors.New("mmdb truncated uint")
		}
		var u uint64
		for i := 0; i < payload; i++ {
			u = (u << 8) | uint64(r.data[off+i])
		}
		return u, off + payload, nil
	case 8: // int32
		if payload > 4 || off+payload > len(r.data) {
			return nil, off, errors.New("mmdb truncated int32")
		}
		var u uint32
		for i := 0; i < payload; i++ {
			u = (u << 8) | uint32(r.data[off+i])
		}
		return int32(u), off + payload, nil
	case 7: // map
		remaining := len(r.data) - off
		if payload < 0 || payload > remaining/2 {
			return nil, off, errors.New("mmdb map exceeds remaining data")
		}
		capHint := payload
		if capHint > 1024 {
			capHint = 1024
		}
		m := make(map[string]any, capHint)
		cur := off
		for i := 0; i < payload; i++ {
			kAny, nextOff, err := r.decodeValue(cur, baseDataStart, depth+1)
			if err != nil {
				return nil, nextOff, err
			}
			vAny, nextOff2, err := r.decodeValue(nextOff, baseDataStart, depth+1)
			if err != nil {
				return nil, nextOff2, err
			}
			if ks, ok := kAny.(string); ok {
				m[ks] = vAny
			}
			cur = nextOff2
		}
		return m, cur, nil
	case 11: // array
		remaining := len(r.data) - off
		if payload < 0 || payload > remaining {
			return nil, off, errors.New("mmdb array exceeds remaining data")
		}
		capHint := payload
		if capHint > 1024 {
			capHint = 1024
		}
		arr := make([]any, 0, capHint)
		cur := off
		for i := 0; i < payload; i++ {
			item, nextOff, err := r.decodeValue(cur, baseDataStart, depth+1)
			if err != nil {
				return nil, nextOff, err
			}
			arr = append(arr, item)
			cur = nextOff
		}
		return arr, cur, nil
	case 14: // boolean
		return payload != 0, off, nil
	case 15: // float
		if off+4 > len(r.data) {
			return nil, off, errors.New("mmdb truncated float")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(r.data[off : off+4]))), off + 4, nil
	default:
		if off+payload > len(r.data) {
			return nil, off, errors.New("mmdb truncated skip")
		}
		return nil, off + payload, nil
	}
}

func asUint64Any(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case int32:
		if x > 0 {
			return uint64(x)
		}
	case float64:
		if x > 0 {
			return uint64(x)
		}
	}
	return 0
}

func asFloat64Any(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case uint64:
		return float64(x)
	case int32:
		return float64(x)
	}
	return 0
}

// GeoIPManager manages hot-reloading City & ASN MMDB databases plus scheduled HTTPS updates.
type GeoIPManager struct {
	mu              sync.RWMutex
	cityPath        string
	cityMtime       int64
	cityReader      *MMDBReader
	asnPath         string
	asnMtime        int64
	asnReader       *MMDBReader
	lastUpdateAt    time.Time
	httpClient      *http.Client
	allowedBaseDirs []string
}

func NewGeoIPManager() *GeoIPManager {
	return &GeoIPManager{}
}

// Refresh checks file mtimes and reloads changed .mmdb databases atomically.
func (g *GeoIPManager) Refresh(cityPath, asnPath string) {
	g.mu.RLock()
	curCityPath, curCityMtime := g.cityPath, g.cityMtime
	curAsnPath, curAsnMtime := g.asnPath, g.asnMtime
	g.mu.RUnlock()

	var newCity *MMDBReader
	var newCityMtime int64
	cityChanged := false
	if cityPath != "" {
		if st, err := os.Stat(cityPath); err == nil {
			mt := st.ModTime().UnixNano()
			if cityPath != curCityPath || mt != curCityMtime {
				if r, rerr := OpenMMDBFile(cityPath); rerr == nil {
					newCity = r
					newCityMtime = mt
					cityChanged = true
				}
			}
		}
	}

	var newAsn *MMDBReader
	var newAsnMtime int64
	asnChanged := false
	if asnPath != "" {
		if st, err := os.Stat(asnPath); err == nil {
			mt := st.ModTime().UnixNano()
			if asnPath != curAsnPath || mt != curAsnMtime {
				if r, rerr := OpenMMDBFile(asnPath); rerr == nil {
					newAsn = r
					newAsnMtime = mt
					asnChanged = true
				}
			}
		}
	}

	if !cityChanged && !asnChanged {
		return
	}
	g.mu.Lock()
	if cityChanged {
		g.cityPath = cityPath
		g.cityMtime = newCityMtime
		g.cityReader = newCity
		g.lastUpdateAt = time.Now().UTC()
	}
	if asnChanged {
		g.asnPath = asnPath
		g.asnMtime = newAsnMtime
		g.asnReader = newAsn
		g.lastUpdateAt = time.Now().UTC()
	}
	g.mu.Unlock()
}

func (g *GeoIPManager) LookupCity(addr netip.Addr) (countryISO, cityName string, lat, lon float64, ok bool) {
	g.mu.RLock()
	r := g.cityReader
	g.mu.RUnlock()
	if r == nil {
		return "", "", 0, 0, false
	}
	return r.LookupCity(addr)
}

func (g *GeoIPManager) LookupASN(addr netip.Addr) (asn uint32, org string, ok bool) {
	g.mu.RLock()
	r := g.asnReader
	g.mu.RUnlock()
	if r == nil {
		return 0, "", false
	}
	return r.LookupASN(addr)
}

func (g *GeoIPManager) Status() (cityLoaded, asnLoaded bool, updatedAt string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.lastUpdateAt.IsZero() {
		updatedAt = g.lastUpdateAt.Format(time.RFC3339)
	}
	return g.cityReader != nil, g.asnReader != nil, updatedAt
}

func isDisallowedExternalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified()
}

func validateGeoIPHTTPSURL(rawURL string, allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid GeoIP URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("disallowed GeoIP URL scheme %q: https required", u.Scheme)
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return fmt.Errorf("disallowed GeoIP download host %q", host)
	}
	if !allowPrivate {
		if strings.EqualFold(host, "localhost") {
			return fmt.Errorf("disallowed GeoIP download host %q", host)
		}
		if ip := net.ParseIP(host); ip != nil && isDisallowedExternalIP(ip) {
			return fmt.Errorf("disallowed non-public GeoIP target IP %s", host)
		}
	}
	return nil
}

func resolvePathWithExistingSymlinks(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	var tail []string
	cur := abs
	for {
		if _, err := os.Lstat(cur); err == nil {
			resolved, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", err
			}
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

func confineGeoIPDBPath(dstPath string, allowedBases []string) (string, error) {
	trimmed := strings.TrimSpace(dstPath)
	if trimmed == "" || strings.HasSuffix(trimmed, string(os.PathSeparator)) {
		return "", errors.New("invalid empty GeoIP destination path")
	}
	resolvedDst, err := resolvePathWithExistingSymlinks(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid GeoIP destination path %q: %w", dstPath, err)
	}
	if len(allowedBases) == 0 {
		allowedBases = []string{"/var/lib/axonwall"}
	}
	for _, base := range allowedBases {
		resolvedBase, err := resolvePathWithExistingSymlinks(base)
		if err != nil {
			continue
		}
		if resolvedDst != resolvedBase && strings.HasPrefix(resolvedDst, resolvedBase+string(os.PathSeparator)) {
			return resolvedDst, nil
		}
	}
	return "", fmt.Errorf("GeoIP path %q escapes allowed base directories", dstPath)
}

func newSafeGeoIPHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, p, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				return nil, splitErr
			}
			ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, h)
			if lookupErr != nil || len(ips) == 0 {
				return nil, fmt.Errorf("failed to resolve GeoIP host %s: %v", h, lookupErr)
			}
			for _, ipAddr := range ips {
				if isDisallowedExternalIP(ipAddr.IP) {
					return nil, fmt.Errorf("disallowed resolved GeoIP IP %s for %s", ipAddr.IP.String(), h)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), p))
		},
	}
	return &http.Client{
		Timeout:   45 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many GeoIP redirects")
			}
			return validateGeoIPHTTPSURL(req.URL.String(), false)
		},
	}
}

// UpdateFromURLs downloads valid .mmdb payloads atomically without disturbing running lookups on failure.
func (g *GeoIPManager) UpdateFromURLs(ctx context.Context, cityURL, asnURL, cityPath, asnPath string) error {
	var errs []string
	g.mu.RLock()
	client := g.httpClient
	allowedBases := append([]string(nil), g.allowedBaseDirs...)
	g.mu.RUnlock()
	allowPrivateForTestClient := client != nil
	if client == nil {
		client = newSafeGeoIPHTTPClient()
	}

	downloadOne := func(rawURL, dstPath string) error {
		if rawURL == "" || dstPath == "" {
			return nil
		}
		if err := validateGeoIPHTTPSURL(rawURL, allowPrivateForTestClient); err != nil {
			return fmt.Errorf("invalid GeoIP download URL for %s: %w", dstPath, err)
		}
		safeDst, err := confineGeoIPDBPath(dstPath, allowedBases)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(rawURL), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, safeDst)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
		if err != nil {
			return err
		}
		if _, err := OpenMMDBBytes(raw); err != nil {
			return fmt.Errorf("downloaded file failed MMDB validation: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(safeDst), 0750); err != nil {
			return err
		}
		tmpFile, err := os.CreateTemp(filepath.Dir(safeDst), filepath.Base(safeDst)+".tmp-*")
		if err != nil {
			return err
		}
		tmp := tmpFile.Name()
		cleanupTmp := true
		defer func() {
			if cleanupTmp {
				_ = os.Remove(tmp)
			}
		}()
		if _, err := tmpFile.Write(raw); err != nil {
			_ = tmpFile.Close()
			return err
		}
		if err := tmpFile.Chmod(0644); err != nil {
			_ = tmpFile.Close()
			return err
		}
		if err := tmpFile.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmp, safeDst); err != nil {
			return err
		}
		cleanupTmp = false
		return nil
	}

	if cityURL != "" && cityURL != netflowMaskedPlaceholder {
		if err := downloadOne(cityURL, cityPath); err != nil {
			errs = append(errs, "city: "+err.Error())
		}
	}
	if asnURL != "" && asnURL != netflowMaskedPlaceholder {
		if err := downloadOne(asnURL, asnPath); err != nil {
			errs = append(errs, "asn: "+err.Error())
		}
	}
	g.Refresh(cityPath, asnPath)
	if len(errs) > 0 {
		log.Printf("[NetFlow] GeoIP DB update warning: %v", errs)
		return errors.New(errs[0])
	}
	return nil
}
