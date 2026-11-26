package engine

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	wsMagicGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsDialTimeout       = 5 * time.Second
	wsIdleReadTimeout   = 5 * time.Minute
	wsWriteTimeout      = 30 * time.Second
	wsMaxControlPayload = 125
)

type ConsoleProxy struct {
	mu sync.Mutex
}

func NewConsoleProxy() *ConsoleProxy {
	return &ConsoleProxy{}
}

// computeAcceptKey calculates RFC 6455 Sec-WebSocket-Accept
func computeAcceptKey(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey + wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func expectedConsoleOriginScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil {
		if strings.EqualFold(r.URL.Scheme, "https") {
			return "https"
		}
		if strings.EqualFold(r.URL.Scheme, "http") {
			return "http"
		}
	}
	if xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); xfp != "" {
		first := strings.TrimSpace(strings.SplitN(xfp, ",", 2)[0])
		if strings.EqualFold(first, "https") {
			return "https"
		}
		if strings.EqualFold(first, "http") {
			return "http"
		}
	}
	return "http"
}

func canonicalHostPort(hostport, scheme string) (string, string, bool) {
	if hostport == "" {
		return "", "", false
	}
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		if h == "" || p == "" {
			return "", "", false
		}
		return strings.ToLower(strings.Trim(h, "[]")), p, true
	}
	trimmed := strings.Trim(hostport, "[]")
	if trimmed == "" || (strings.Contains(trimmed, ":") && net.ParseIP(trimmed) == nil) {
		return "", "", false
	}
	defaultPort := "80"
	if strings.EqualFold(scheme, "https") {
		defaultPort = "443"
	}
	return strings.ToLower(trimmed), defaultPort, true
}

func validateConsoleOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	origScheme := strings.ToLower(u.Scheme)
	if origScheme != "http" && origScheme != "https" {
		return false
	}
	reqScheme := expectedConsoleOriginScheme(r)
	if origScheme != reqScheme {
		return false
	}
	origHost, origPort, ok1 := canonicalHostPort(u.Host, origScheme)
	reqHost, reqPort, ok2 := canonicalHostPort(r.Host, reqScheme)
	return ok1 && ok2 && origHost == reqHost && origPort == reqPort
}

type deadlineReader struct {
	r            io.Reader
	conn         net.Conn
	timeout      time.Duration
	lastActivity *atomic.Int64
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if d.conn != nil {
		_ = d.conn.SetReadDeadline(time.Now().Add(d.timeout))
	}
	n, err := d.r.Read(p)
	if n > 0 && d.lastActivity != nil {
		d.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
}

func (p *ConsoleProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	targetType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	if targetType == "" {
		targetType = "vnc"
	}
	idStr := strings.TrimSpace(r.URL.Query().Get("vmid"))
	if idStr == "" {
		idStr = strings.TrimSpace(r.URL.Query().Get("ctid"))
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		http.Error(w, "Invalid or missing vmid/ctid parameter", http.StatusBadRequest)
		return
	}

	var socketPath string
	switch targetType {
	case "vnc":
		socketPath = fmt.Sprintf("/run/axonwall/vnc/vm-%d.sock", id)
	case "serial":
		socketPath = fmt.Sprintf("/run/axonwall/serial/vm-%d.sock", id)
	case "lxc":
		socketPath = fmt.Sprintf("/run/axonwall/lxc/ct-%d.sock", id)
	default:
		http.Error(w, "Unsupported console type: "+targetType, http.StatusBadRequest)
		return
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		http.Error(w, fmt.Sprintf("Console socket not found for target %d (%s). Is the workload running?", id, socketPath), http.StatusNotFound)
		return
	}

	// Verify WebSocket upgrade request and exact Origin scheme+host+port
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if !validateConsoleOrigin(origin, r) {
			http.Error(w, "Cross-origin WebSocket connection rejected", http.StatusForbidden)
			return
		}
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "Upgrade header must be websocket", http.StatusBadRequest)
		return
	}
	clientKey := r.Header.Get("Sec-WebSocket-Key")
	if clientKey == "" {
		http.Error(w, "Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Connect to the target Unix domain socket
	backendConn, err := net.DialTimeout("unix", socketPath, wsDialTimeout)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to backend socket %s: %v", socketPath, err), http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijack unsupported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[ConsoleProxy] Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	// Negotiate subprotocol if requested (noVNC supports 'binary')
	subproto := ""
	for _, p := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		p = strings.TrimSpace(p)
		if p == "binary" {
			subproto = "Sec-WebSocket-Protocol: binary\r\n"
			break
		}
	}

	acceptKey := computeAcceptKey(clientKey)
	handshake := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"%s"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", subproto, acceptKey)

	_ = clientConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	if _, err := clientBuf.WriteString(handshake); err != nil {
		return
	}
	if err := clientBuf.Flush(); err != nil {
		return
	}

	errChan := make(chan error, 2)
	var writeMu sync.Mutex
	safeWriteFrame := func(payload []byte, opcode byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = clientConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
		return writeWSFrame(clientConn, payload, opcode)
	}

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: Backend -> WebSocket Client (pack into binary frames)
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			_ = backendConn.SetReadDeadline(time.Now().Add(wsIdleReadTimeout))
			n, err := backendConn.Read(buf)
			if n > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if wErr := safeWriteFrame(buf[:n], 0x2); wErr != nil {
					errChan <- wErr
					return
				}
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if time.Since(time.Unix(0, lastActivity.Load())) < wsIdleReadTimeout {
						continue
					}
				}
				errChan <- err
				return
			}
		}
	}()

	// Goroutine 2: WebSocket Client -> Backend (decode WS frames, write to unix socket)
	allowTextFrames := targetType == "serial" || targetType == "lxc"
	go func() {
		defer wg.Done()
		cr := &deadlineReader{
			r:            clientBuf,
			conn:         clientConn,
			timeout:      wsIdleReadTimeout,
			lastActivity: &lastActivity,
		}
		forwardClientFramesWithOpts(cr, backendConn, safeWriteFrame, errChan, allowTextFrames)
	}()

	<-errChan
	_ = backendConn.Close()
	_ = clientConn.Close()
	wg.Wait()
}

// forwardClientFrames decodes client WebSocket frames for binary VNC/RFB sockets.
func forwardClientFrames(clientBuf io.Reader, backendConn net.Conn, safeWriteFrame func([]byte, byte) error, errChan chan<- error) {
	forwardClientFramesWithOpts(clientBuf, backendConn, safeWriteFrame, errChan, false)
}

func forwardClientFramesWithOpts(clientBuf io.Reader, backendConn net.Conn, safeWriteFrame func([]byte, byte) error, errChan chan<- error, allowText bool) {
	const maxReassembledMessage = 10 * 1024 * 1024
	var fragBuf []byte
	inFragment := false
	for {
		payload, opcode, fin, err := readWSFrame(clientBuf)
		if err != nil {
			errChan <- err
			return
		}
		switch opcode {
		case 0x8: // Close frame
			_ = safeWriteFrame(nil, 0x8)
			errChan <- io.EOF
			return
		case 0x9: // Ping
			if len(payload) > wsMaxControlPayload {
				errChan <- fmt.Errorf("websocket protocol violation: ping payload %d exceeds %d-byte limit", len(payload), wsMaxControlPayload)
				return
			}
			if err := safeWriteFrame(payload, 0xA); err != nil { // Pong
				errChan <- err
				return
			}
			continue
		case 0xA: // Pong: ignore, never forward to the backend.
			continue
		case 0x1: // Text frame: allow for xterm.js serial/lxc PTY consoles, reject for binary RFB/VNC.
			if !allowText {
				errChan <- fmt.Errorf("websocket text frame rejected: console transport is binary-only")
				return
			}
			if inFragment {
				errChan <- fmt.Errorf("websocket protocol violation: new text frame while a fragmented message is incomplete")
				return
			}
			if fin {
				if len(payload) > 0 {
					_ = backendConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
					if _, err := backendConn.Write(payload); err != nil {
						errChan <- err
						return
					}
				}
				continue
			}
			fragBuf = append(fragBuf[:0], payload...)
			inFragment = true
		case 0x2: // Binary frame: start of a (possibly fragmented) message.
			if inFragment {
				errChan <- fmt.Errorf("websocket protocol violation: new binary frame while a fragmented message is incomplete")
				return
			}
			if fin {
				if len(payload) > 0 {
					_ = backendConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
					if _, err := backendConn.Write(payload); err != nil {
						errChan <- err
						return
					}
				}
				continue
			}
			fragBuf = append(fragBuf[:0], payload...)
			inFragment = true
		case 0x0: // Continuation frame.
			if !inFragment {
				errChan <- fmt.Errorf("websocket protocol violation: continuation frame with no fragmented message in progress")
				return
			}
			if len(fragBuf)+len(payload) > maxReassembledMessage {
				errChan <- fmt.Errorf("websocket reassembled message exceeds 10MB limit")
				return
			}
			fragBuf = append(fragBuf, payload...)
			if !fin {
				continue
			}
			if len(fragBuf) > 0 {
				_ = backendConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
				if _, err := backendConn.Write(fragBuf); err != nil {
					errChan <- err
					return
				}
			}
			fragBuf = fragBuf[:0]
			inFragment = false
		default:
			errChan <- fmt.Errorf("websocket protocol violation: unsupported opcode 0x%x", opcode)
			return
		}
	}
}

func writeWSFrame(w io.Writer, payload []byte, opcode byte) error {
	if opcode >= 0x8 && len(payload) > wsMaxControlPayload {
		return fmt.Errorf("websocket control frame 0x%x payload %d exceeds %d-byte RFC 6455 limit", opcode, len(payload), wsMaxControlPayload)
	}
	length := len(payload)
	frame := make([]byte, 10+length)
	frame[0] = 0x80 | (opcode & 0x0F) // FIN + opcode

	headerLen := 2
	if length <= 125 {
		frame[1] = byte(length)
	} else if length <= 65535 {
		frame[1] = 126
		binary.BigEndian.PutUint16(frame[2:4], uint16(length))
		headerLen = 4
	} else {
		frame[1] = 127
		binary.BigEndian.PutUint64(frame[2:10], uint64(length))
		headerLen = 10
	}

	if length > 0 {
		copy(frame[headerLen:headerLen+length], payload)
	}
	_, err := w.Write(frame[:headerLen+length])
	return err
}

func readWSFrame(r io.Reader) ([]byte, byte, bool, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, 0, false, err
	}

	fin := (head[0] & 0x80) != 0
	opcode := head[0] & 0x0F
	masked := (head[1] & 0x80) != 0
	payloadLen := int64(head[1] & 0x7F)

	if payloadLen == 126 {
		var extLen uint16
		if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
			return nil, 0, false, err
		}
		payloadLen = int64(extLen)
	} else if payloadLen == 127 {
		var extLen uint64
		if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
			return nil, 0, false, err
		}
		if extLen > 10*1024*1024 {
			return nil, 0, false, fmt.Errorf("websocket frame payload exceeds 10MB limit")
		}
		payloadLen = int64(extLen)
	}

	if opcode >= 0x8 {
		if !fin {
			return nil, 0, false, fmt.Errorf("websocket protocol violation: fragmented control frame 0x%x", opcode)
		}
		if payloadLen > wsMaxControlPayload {
			return nil, 0, false, fmt.Errorf("websocket protocol violation: control frame payload %d exceeds %d-byte limit", payloadLen, wsMaxControlPayload)
		}
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return nil, 0, false, err
		}
	}

	if payloadLen > 10*1024*1024 {
		return nil, 0, false, fmt.Errorf("websocket frame payload exceeds 10MB limit")
	}

	data := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, 0, false, err
	}

	if masked {
		for i := 0; i < len(data); i++ {
			data[i] ^= maskKey[i%4]
		}
	}

	return data, opcode, fin, nil
}
