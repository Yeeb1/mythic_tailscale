package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/tsnet"
)

type Config struct {
	AuthKey    string `json:"auth_key"`
	ControlURL string `json:"control_url"`
	Hostname   string `json:"hostname"`
	ListenPort string `json:"listen_port"`
	TCPPort    string `json:"tcp_port"`
}

func loadConfig() Config {
	cfg := Config{
		Hostname:   "mythic-c2",
		ListenPort: "8080",
	}

	// Try config.json in same directory as binary
	exePath, _ := os.Executable()
	configPath := filepath.Join(filepath.Dir(exePath), "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Try current directory
		data, err = os.ReadFile("config.json")
	}
	if err == nil {
		json.Unmarshal(data, &cfg)
	}

	// Environment overrides
	if v := os.Getenv("TS_AUTH_KEY"); v != "" {
		cfg.AuthKey = v
	}
	if v := os.Getenv("TS_CONTROL_URL"); v != "" {
		cfg.ControlURL = v
	}
	if v := os.Getenv("TS_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("TS_LISTEN_PORT"); v != "" {
		cfg.ListenPort = v
	}
	if v := os.Getenv("TS_TCP_PORT"); v != "" {
		cfg.TCPPort = v
	}

	return cfg
}

func getMythicAddr() string {
	if v := os.Getenv("MYTHIC_ADDRESS"); v != "" {
		return v
	}
	return "http://mythic_server:17443/agent_message"
}

func main() {
	cfg := loadConfig()
	mythicAddr := getMythicAddr()

	if cfg.AuthKey == "" {
		log.Println("[!] No auth_key configured. Set in config.json or TS_AUTH_KEY env var.")
		log.Println("[!] Configure via Mythic UI: C2 Profiles > tailscale > config")
		log.Println("[*] Waiting for configuration...")
		for {
			time.Sleep(10 * time.Second)
			cfg = loadConfig()
			if cfg.AuthKey != "" {
				break
			}
		}
		log.Println("[+] Configuration detected, starting...")
	}

	log.Printf("[*] Tailscale C2 Server starting")
	log.Printf("[*] Hostname: %s", cfg.Hostname)
	log.Printf("[*] Listen port: %s", cfg.ListenPort)
	log.Printf("[*] Control URL: %s", cfg.ControlURL)
	log.Printf("[*] Mythic address: %s", mythicAddr)

	// Use disk-based state dir so the server persists on the tailnet across restarts
	exePath, _ := os.Executable()
	stateDir := filepath.Join(filepath.Dir(exePath), "ts-state")
	os.MkdirAll(stateDir, 0700)

	srv := &tsnet.Server{
		Hostname:  cfg.Hostname,
		AuthKey:   cfg.AuthKey,
		Ephemeral: false,
		Dir:       stateDir,
	}
	if cfg.ControlURL != "" {
		srv.ControlURL = cfg.ControlURL
	}

	// Suppress verbose tsnet logging
	srv.Logf = func(format string, args ...interface{}) {}

	defer srv.Close()

	ln, err := srv.Listen("tcp", ":"+cfg.ListenPort)
	if err != nil {
		log.Fatalf("[!] Failed to listen on tailnet: %v", err)
	}
	log.Printf("[+] Listening on tailnet %s:%s", cfg.Hostname, cfg.ListenPort)

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	mux := http.NewServeMux()

	// Debug: catch-all to log unmatched requests
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] Unmatched request: %s %s (Host: %s)", r.Method, r.URL.String(), r.Host)
		http.NotFound(w, r)
	})

	mux.HandleFunc("/agent_message", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] Matched /agent_message: %s %s (Host: %s)", r.Method, r.URL.String(), r.Host)
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[!] Failed to read agent request: %v", err)
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		log.Printf("[>] Forwarding to Mythic: %s (body len: %d)", mythicAddr, len(body))
		log.Printf("[>] Body preview: %s", string(body[:min(200, len(body))]))

		// Forward to Mythic (must include "mythic" header with C2 profile name)
		mythicReq, _ := http.NewRequest("POST", mythicAddr, bytes.NewReader(body))
		mythicReq.Header.Set("Content-Type", "application/octet-stream")
		mythicReq.Header.Set("mythic", "tailscale")
		resp, err := httpClient.Do(mythicReq)
		if err != nil {
			log.Printf("[!] Failed to forward to Mythic: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[!] Failed to read Mythic response: %v", err)
			http.Error(w, "upstream read error", http.StatusBadGateway)
			return
		}

		log.Printf("[<] Mythic response: HTTP %d, body len: %d", resp.StatusCode, len(respBody))
		if resp.StatusCode != 200 {
			log.Printf("[<] Mythic response body: %s", string(respBody[:min(500, len(respBody))]))
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})

	// Start TCP listener if configured
	if cfg.TCPPort != "" && cfg.TCPPort != "0" {
		tcpLn, err := srv.Listen("tcp", ":"+cfg.TCPPort)
		if err != nil {
			log.Fatalf("[!] Failed to listen TCP on tailnet: %v", err)
		}
		log.Printf("[+] TCP listener on tailnet %s:%s", cfg.Hostname, cfg.TCPPort)
		go serveTCP(tcpLn, mythicAddr, httpClient)
	}

	log.Printf("[+] Tailscale C2 server ready")
	if err := http.Serve(ln, mux); err != nil {
		log.Fatalf("[!] HTTP server error: %v", err)
	}
}

// serveTCP accepts TCP connections and handles length-prefixed binary framing.
// Protocol: [4-byte big-endian length][payload]
// Payload is the same base64(UUID + JSON) format used by HTTP.
func serveTCP(ln net.Listener, mythicAddr string, httpClient *http.Client) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TCP] Accept error: %v", err)
			continue
		}
		log.Printf("[TCP] New connection from %s", conn.RemoteAddr())
		go handleTCPConn(conn, mythicAddr, httpClient)
	}
}

func handleTCPConn(conn net.Conn, mythicAddr string, httpClient *http.Client) {
	defer conn.Close()

	for {
		// Read 4-byte length header
		var msgLen uint32
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			if err != io.EOF {
				log.Printf("[TCP] Read length error: %v", err)
			}
			return
		}

		if msgLen == 0 || msgLen > 16*1024*1024 { // 16MB max
			log.Printf("[TCP] Invalid message length: %d", msgLen)
			return
		}

		// Read payload
		payload := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			log.Printf("[TCP] Read payload error: %v", err)
			return
		}

		log.Printf("[TCP>] Forwarding to Mythic (payload len: %d)", len(payload))

		// Forward to Mythic via HTTP POST (same as HTTP handler)
		mythicReq, _ := http.NewRequest("POST", mythicAddr, bytes.NewReader(payload))
		mythicReq.Header.Set("Content-Type", "application/octet-stream")
		mythicReq.Header.Set("mythic", "tailscale")

		resp, err := httpClient.Do(mythicReq)
		if err != nil {
			log.Printf("[TCP] Forward to Mythic failed: %v", err)
			// Send zero-length response to signal error
			binary.Write(conn, binary.BigEndian, uint32(0))
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("[TCP] Read Mythic response failed: %v", err)
			binary.Write(conn, binary.BigEndian, uint32(0))
			continue
		}

		log.Printf("[TCP<] Mythic response: HTTP %d, body len: %d", resp.StatusCode, len(respBody))

		// Send response with length prefix
		if err := binary.Write(conn, binary.BigEndian, uint32(len(respBody))); err != nil {
			log.Printf("[TCP] Write response length failed: %v", err)
			return
		}
		if _, err := conn.Write(respBody); err != nil {
			log.Printf("[TCP] Write response body failed: %v", err)
			return
		}
	}
}
