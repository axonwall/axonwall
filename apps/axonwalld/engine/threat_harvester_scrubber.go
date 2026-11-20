package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var (
	// R4-A-M6: the scheme group is optional so a schemeless
	// `Authorization: <token>` is redacted too. A bare token is
	// still a credential; the old pattern only matched Bearer /
	// Basic / Token and let raw tokens through to the spool, the
	// teacher LLM, and the S3 export.
	reAuthHeader = regexp.MustCompile(`(?i)(Authorization:\s*(?:(?:Bearer|Basic|Token)\s+)?)([A-Za-z0-9._~+/=-]{6,})`)
	reJwtToken   = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b`)
	reApiKey     = regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b`)
	// R4-A-M6: `sessionid` and `session` are secret keys too — the
	// old set only had `session_id` / `sid`, so `Cookie:
	// sessionid=...` and `session=...` leaked. `sessionid` must
	// precede `session` in the alternation or `sessionid=...`
	// would match `session` and leave `id=...` behind.
	reSecretKV = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api_key|apikey|access_token|refresh_token|sessionid|session|session_id|sid)(\s*[=:]\s*)([^\s&"';,}{<>]+)`)
	// R4-A-M6: Cookie / Set-Cookie header values are redacted as a
	// whole — a session cookie is a credential regardless of the
	// key name inside it.
	reCookieHeader    = regexp.MustCompile(`(?im)^(Cookie:[ \t]*)[^\r\n]*`)
	reSetCookieHeader = regexp.MustCompile(`(?im)^(Set-Cookie:[ \t]*)[^\r\n]*`)
	rePemPrivKey      = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	reEmailAddr       = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,12}\b`)
	reCardCand        = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	reEmbeddedV4      = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reEmbeddedV6      = regexp.MustCompile(`(?i)(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}`)
)

func passesLuhnCheck(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// ScrubThreatPayload applies always-on pre-disk structural secret & PII redaction
// while keeping attack syntax (SQLi, shell metacharacters, JNDI, command paths)
// intact for LLM reasoning.
func ScrubThreatPayload(raw string) (string, int) {
	if raw == "" {
		return "", 0
	}
	count := 0
	out := raw

	out = rePemPrivKey.ReplaceAllStringFunc(out, func(_ string) string {
		count++
		return "<REDACTED:PRIVATE_KEY>"
	})

	out = reAuthHeader.ReplaceAllStringFunc(out, func(m string) string {
		sub := reAuthHeader.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		count++
		return sub[1] + "<REDACTED:AUTH_TOKEN>"
	})

	out = reJwtToken.ReplaceAllStringFunc(out, func(_ string) string {
		count++
		return "<REDACTED:JWT>"
	})

	// R4-A-M6: Cookie / Set-Cookie header values are credentials
	// regardless of the key names inside them. Redact the whole
	// header value (before the KV pass, so a `sessionid=...` inside
	// a Cookie line is not double-counted as a secret param).
	out = reCookieHeader.ReplaceAllStringFunc(out, func(m string) string {
		sub := reCookieHeader.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		count++
		return sub[1] + "<REDACTED:COOKIE>"
	})

	out = reSetCookieHeader.ReplaceAllStringFunc(out, func(m string) string {
		sub := reSetCookieHeader.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		count++
		return sub[1] + "<REDACTED:COOKIE>"
	})

	out = reApiKey.ReplaceAllStringFunc(out, func(_ string) string {
		count++
		return "<REDACTED:API_KEY>"
	})

	out = reSecretKV.ReplaceAllStringFunc(out, func(m string) string {
		sub := reSecretKV.FindStringSubmatch(m)
		if len(sub) < 4 {
			return m
		}
		if strings.HasPrefix(sub[3], "<REDACTED:") {
			return m
		}
		count++
		return sub[1] + sub[2] + "<REDACTED:SECRET_PARAM>"
	})

	out = reEmailAddr.ReplaceAllStringFunc(out, func(_ string) string {
		count++
		return "<REDACTED:EMAIL>"
	})

	out = reCardCand.ReplaceAllStringFunc(out, func(m string) string {
		var b strings.Builder
		b.Grow(len(m))
		for i := 0; i < len(m); i++ {
			if m[i] >= '0' && m[i] <= '9' {
				b.WriteByte(m[i])
			}
		}
		if passesLuhnCheck(b.String()) {
			count++
			return "<REDACTED:CREDIT_CARD>"
		}
		return m
	})

	return out, count
}

// CryptoPanAnonymizer implements prefix-preserving AES-128 IP pseudonymization
// (Crypto-PAn) and keyed HMAC hostname pseudonymization.
type CryptoPanAnonymizer struct {
	block   cipher.Block
	pad     [16]byte
	hmacKey []byte

	mu    sync.Mutex
	cache map[string]string
}

// NewCryptoPanAnonymizer derives encryption and padding keys from salt.
// If salt is empty, it falls back to a random process-lifetime key or persists
// one under fallbackSaltFile when non-empty.
func NewCryptoPanAnonymizer(salt string, fallbackSaltFile string) (*CryptoPanAnonymizer, error) {
	effectiveSalt := strings.TrimSpace(salt)
	if effectiveSalt == "" && fallbackSaltFile != "" {
		if b, err := os.ReadFile(fallbackSaltFile); err == nil {
			effectiveSalt = strings.TrimSpace(string(b))
		}
		if effectiveSalt == "" {
			rnd := make([]byte, 32)
			_, _ = rand.Read(rnd)
			effectiveSalt = hex.EncodeToString(rnd)
			_ = os.MkdirAll(filepath.Dir(fallbackSaltFile), 0700)
			_ = os.WriteFile(fallbackSaltFile, []byte(effectiveSalt+"\n"), 0600)
		}
	}
	if effectiveSalt == "" {
		rnd := make([]byte, 32)
		_, _ = rand.Read(rnd)
		effectiveSalt = hex.EncodeToString(rnd)
	}

	digest := sha256.Sum256([]byte("axonwall-cryptopan-v1:" + effectiveSalt))
	block, err := aes.NewCipher(digest[:16])
	if err != nil {
		return nil, err
	}
	var pad [16]byte
	block.Encrypt(pad[:], digest[16:32])

	hmacDigest := sha256.Sum256([]byte("axonwall-hostpan-v1:" + effectiveSalt))
	return &CryptoPanAnonymizer{
		block:   block,
		pad:     pad,
		hmacKey: hmacDigest[:],
		cache:   make(map[string]string, 1024),
	}, nil
}

// AnonymizeIP pseudonymizes an IPv4 or IPv6 string while strictly preserving
// subnet prefix relationships (/8, /16, /24, /64, etc.).
func (c *CryptoPanAnonymizer) AnonymizeIP(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || c == nil {
		return raw
	}
	if trimmed == "0.0.0.0" || trimmed == "::" {
		return trimmed
	}

	c.mu.Lock()
	if hit, ok := c.cache[trimmed]; ok {
		c.mu.Unlock()
		return hit
	}
	c.mu.Unlock()

	ip := net.ParseIP(trimmed)
	if ip == nil {
		return raw
	}

	var result string
	if v4 := ip.To4(); v4 != nil {
		orig := binary.BigEndian.Uint32(v4)
		pad32 := binary.BigEndian.Uint32(c.pad[:4])
		var flipMask uint32
		var inBlock [16]byte
		var outBlock [16]byte
		copy(inBlock[:], c.pad[:])

		for pos := 0; pos < 32; pos++ {
			var prefixPat uint32
			if pos > 0 {
				prefixMask := ^uint32(0) << (32 - pos)
				prefixPat = (orig & prefixMask) | (pad32 & ^prefixMask)
			} else {
				prefixPat = pad32
			}
			binary.BigEndian.PutUint32(inBlock[:4], prefixPat)
			c.block.Encrypt(outBlock[:], inBlock[:])
			if (outBlock[0] & 0x80) != 0 {
				flipMask |= uint32(1) << (31 - pos)
			}
		}
		anon := orig ^ flipMask
		var outBytes [4]byte
		binary.BigEndian.PutUint32(outBytes[:], anon)
		result = net.IP(outBytes[:]).String()
	} else {
		v6 := ip.To16()
		if v6 == nil {
			return raw
		}
		var out [16]byte
		var inBlock [16]byte
		var outBlock [16]byte
		copy(out[:], v6)
		for pos := 0; pos < 128; pos++ {
			copy(inBlock[:], c.pad[:])
			fullBytes := pos / 8
			remBits := pos % 8
			for b := 0; b < fullBytes; b++ {
				inBlock[b] = v6[b]
			}
			if remBits > 0 {
				mask := byte(0xFF) << (8 - remBits)
				inBlock[fullBytes] = (v6[fullBytes] & mask) | (c.pad[fullBytes] & ^mask)
			}
			c.block.Encrypt(outBlock[:], inBlock[:])
			bit := (outBlock[0] >> 7) & 1
			out[pos/8] ^= bit << (7 - (pos % 8))
		}
		result = net.IP(out[:]).String()
	}

	c.mu.Lock()
	if len(c.cache) > 16384 {
		c.cache = make(map[string]string, 1024)
	}
	c.cache[trimmed] = result
	c.mu.Unlock()
	return result
}

// AnonymizeHostname deterministically hashes sensitive hostnames via keyed HMAC.
func (c *CryptoPanAnonymizer) AnonymizeHostname(host string) string {
	clean := strings.TrimSpace(host)
	if clean == "" || c == nil {
		return host
	}
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write([]byte(strings.ToLower(clean)))
	sum := mac.Sum(nil)
	return "h-" + hex.EncodeToString(sum[:6]) + ".anon.axonwall"
}

// AnonymizeText rewrites embedded IPv4 and IPv6 literals inside Causal DSL traces or payloads.
func (c *CryptoPanAnonymizer) AnonymizeText(text string) string {
	if text == "" || c == nil {
		return text
	}
	scrubbed := reEmbeddedV4.ReplaceAllStringFunc(text, func(ipStr string) string {
		return c.AnonymizeIP(ipStr)
	})
	return reEmbeddedV6.ReplaceAllStringFunc(scrubbed, func(cand string) string {
		ip := net.ParseIP(cand)
		if ip == nil || ip.To4() != nil {
			return cand
		}
		return c.AnonymizeIP(cand)
	})
}
