package httpapi

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/vps-manager/back/internal/auth"
	"github.com/vps-manager/back/internal/config"
	"github.com/vps-manager/back/internal/hwfp"
	"github.com/vps-manager/back/internal/hub"
)

func writeJSON(conn *websocket.Conn, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = conn.WriteMessage(websocket.TextMessage, b)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  256 * 1024,
	WriteBufferSize: 256 * 1024,
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Server struct {
	cfg *config.Config
	hub *hub.Hub
}

func New(c *config.Config, h *hub.Hub) *Server {
	return &Server{cfg: c, hub: h}
}

type loginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/ws/agent", s.handleAgentWS)
	mux.HandleFunc("/ws/ui", s.handleUIWS)
	return cors(logRequests(mux))
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var b loginBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if b.Username != s.cfg.AdminUser || b.Password != s.cfg.AdminPass {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tok, err := auth.IssueToken(s.cfg.JWTSecret, b.Username)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret != s.cfg.AgentSecret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	host := r.URL.Query().Get("hostname")
	if host == "" {
		host = "unknown"
	}
	hwJSON := r.URL.Query().Get("hw")
	legacyMID := r.URL.Query().Get("machine_id")
	machineKey, err := resolveHardwareKey(s.cfg.SecretPepper, hwJSON, legacyMID)
	if err != nil {
		log.Printf("agent rejected invalid hw profile: %v", err)
		http.Error(w, "bad hw profile", http.StatusBadRequest)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	id := genAgentID()
	s.hub.RegisterAgent(id, host, machineKey, conn)
	if machineKey != "" {
		log.Printf("agent connected: %s hostname=%s fp=%.12s…", id, host, machineKey)
	} else {
		log.Printf("agent connected: %s hostname=%s (no hardware profile; dedupe by hostname only)", id, host)
	}

	on, arSec := s.hub.AutoRestartState()
	writeJSON(conn, map[string]any{
		"type":                    "config",
		"screenshot_interval_sec": s.hub.ScreenshotInterval(),
		"auto_restart_enabled":    on,
		"auto_restart_sec":        arSec,
	})

	go func() {
		defer func() {
			s.hub.UnregisterAgent(id)
			_ = conn.Close()
			log.Printf("agent gone: %s", id)
		}()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			s.hub.HandleAgentMessage(id, msg)
		}
	}()
}

func (s *Server) handleUIWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			token = strings.TrimSpace(h[7:])
		}
	}
	if _, err := auth.ParseToken(s.cfg.JWTSecret, token); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	uic := &hub.UIConn{Conn: conn}
	s.hub.RegisterUI(uic)
	log.Printf("ui connected")

	go func() {
		defer func() {
			s.hub.UnregisterUI(uic)
			_ = conn.Close()
			log.Printf("ui disconnected")
		}()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			s.handleUIMessage(msg)
		}
	}()
}

func (s *Server) handleUIMessage(raw []byte) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	t, _ := m["type"].(string)
	switch t {
	case "run_command":
		cmd := wsString(m["cmd"])
		vpsID := wsString(m["vps_id"])
		if vpsID == "" || cmd == "" {
			log.Printf("ui run_command ignored: empty vps_id or cmd (vps_id=%q cmd=%q)", vpsID, cmd)
			return
		}
		if !s.hub.SendToAgent(vpsID, hub.Command(cmd), nil) {
			log.Printf("ui run_command: no agent id=%q (disconnected or unknown)", vpsID)
		}
	case "broadcast_command":
		cmd := wsString(m["cmd"])
		if cmd == "" {
			return
		}
		s.hub.BroadcastCommand(hub.Command(cmd), nil)
	case "set_auto_restart":
		en, _ := m["enabled"].(bool)
		secf, _ := m["interval_sec"].(float64)
		sec := int(secf)
		s.hub.SetAutoRestart(en, sec)
	case "set_screenshot_interval":
		secf, _ := m["interval_sec"].(float64)
		sec := int(secf)
		s.hub.UpdateScreenshotInterval(sec)
	case "agent_rpc":
		vpsID := wsString(m["vps_id"])
		reqID := wsString(m["request_id"])
		if vpsID == "" || reqID == "" {
			log.Printf("ui agent_rpc ignored: missing vps_id or request_id")
			return
		}
		out := make(map[string]any, len(m))
		for k, v := range m {
			if k == "vps_id" {
				continue
			}
			out[k] = v
		}
		if !s.hub.SendJSONToAgent(vpsID, out) {
			s.hub.BroadcastUI(map[string]any{
				"type":       "agent_rpc_result",
				"vps_id":     vpsID,
				"request_id": reqID,
				"ok":         false,
				"error":      "agent offline or unknown id",
			})
		}
	default:
		log.Printf("ui msg: %s", t)
	}
}

var agentCounter uint64

// resolveHardwareKey prefers JSON `hw`; falls back to legacy `machine_id` (Windows MachineGuid only).
func resolveHardwareKey(pepper, hwJSON, legacyMID string) (string, error) {
	hwJSON = strings.TrimSpace(hwJSON)
	legacyMID = strings.TrimSpace(legacyMID)
	if hwJSON != "" {
		return hwfp.FromJSON(pepper, hwJSON)
	}
	if legacyMID != "" {
		return hwfp.FromLegacyMachineGUID(pepper, legacyMID), nil
	}
	return "", nil
}

func genAgentID() string {
	return time.Now().UTC().Format("20060102150405") + "-" + itoa(atomic.AddUint64(&agentCounter, 1))
}

// wsString coerces JSON-decoded scalar values (string, float64, etc.) to string.
func wsString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%.0f", x)
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func itoa(u uint64) string {
	const digits = "0123456789"
	if u == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = digits[u%10]
		u /= 10
	}
	return string(b[i:])
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
