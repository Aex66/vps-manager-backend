package hub

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Command string

const (
	CmdRefreshAll      Command = "refresh_all"
	CmdRestartYummy    Command = "restart_yummy"
	CmdKillYummy       Command = "kill_yummy"
	CmdStartYummy      Command = "start_yummy"
	CmdKillExecutor    Command = "kill_executor"
	CmdStartExecutor   Command = "start_executor"
	CmdRestartExecutor Command = "restart_executor"
	CmdKillRoblox      Command = "kill_roblox"
	CmdGrabCookies     Command = "grab_cookies"
	CmdScreenshot      Command = "screenshot"
	CmdStopVPS         Command = "stop_vps"
	CmdPing            Command = "ping"
)

type VPSInfo struct {
	ID             string  `json:"id"`
	Hostname       string  `json:"hostname"`
	MachineID      string  `json:"machine_id,omitempty"`
	LocalIP        string  `json:"local_ip,omitempty"`
	Connected      bool    `json:"connected"`
	LastSeen       int64   `json:"last_seen"`
	HasMetrics     bool    `json:"has_metrics"`
	CpuPercent     float64 `json:"cpu_percent"`
	Cores          int     `json:"cores"`
	Threads        int     `json:"threads"`
	VoltRunning    bool    `json:"volt_running"`
	WebrbRunning   bool    `json:"webrb_running"`
	UptimeSec      int64   `json:"uptime_sec,omitempty"`
	NetSentMbps    float64 `json:"net_sent_mbps"`
	NetRecvMbps    float64 `json:"net_recv_mbps"`
	ScreenshotB64  string  `json:"screenshot_b64,omitempty"`
	CookiesSnippet string  `json:"cookies_snippet,omitempty"`
}

type AgentConn struct {
	ID         string
	Hostname   string
	MachineID  string // Windows MachineGuid / Linux machine-id; reconnect dedupe key
	Conn       *websocket.Conn
	mu         sync.Mutex

	CpuPercent   float64
	Cores        int
	Threads      int
	VoltRunning  bool
	WebrbRunning bool
	LocalIP      string
	UptimeSec    int64
	NetSentMbps  float64
	NetRecvMbps  float64
	MetricsTS    int64 // 0 = no sample yet
}

type UIConn struct {
	Conn *websocket.Conn
	mu   sync.Mutex
}

type Hub struct {
	mu sync.RWMutex

	agents map[string]*AgentConn
	ui     map[*UIConn]struct{}

	// auto-restart
	autoRestartOn   bool
	autoRestartSec  int
	autoRestartStop chan struct{}

	cfgScreenshotIntervalSec int
}

func NewHub(screenshotIntervalDefault int, autoRestartDefaultSec int) *Hub {
	if autoRestartDefaultSec < 60 {
		autoRestartDefaultSec = 3600
	}
	if screenshotIntervalDefault < 3 {
		screenshotIntervalDefault = 5
	}
	return &Hub{
		agents:                   make(map[string]*AgentConn),
		ui:                       make(map[*UIConn]struct{}),
		autoRestartSec:           autoRestartDefaultSec,
		cfgScreenshotIntervalSec: screenshotIntervalDefault,
	}
}

func (h *Hub) RegisterAgent(id, hostname, machineID string, c *websocket.Conn) *AgentConn {
	hostKey := strings.TrimSpace(hostname)
	if hostKey == "" {
		hostKey = "unknown"
	}
	mid := strings.TrimSpace(machineID)
	h.mu.Lock()
	// Reconnect dedupe: prefer machine_id (stable per OS install); else hostname (legacy agents).
	var stale []*websocket.Conn
	for existingID, a := range h.agents {
		ah := strings.TrimSpace(a.Hostname)
		am := strings.TrimSpace(a.MachineID)
		same := false
		switch {
		case mid != "":
			if strings.EqualFold(am, mid) {
				same = true
			} else if am == "" && strings.EqualFold(ah, hostKey) {
				// Same box after upgrade: old session had no machine_id, new one does.
				same = true
			}
		default:
			// Legacy agent: only dedupe when neither connection reported a machine id.
			if am == "" && strings.EqualFold(ah, hostKey) {
				same = true
			}
		}
		if same {
			delete(h.agents, existingID)
			stale = append(stale, a.Conn)
		}
	}
	ac := &AgentConn{ID: id, Hostname: hostname, MachineID: mid, Conn: c}
	h.agents[id] = ac
	list := h.snapshotVPSListLocked()
	h.mu.Unlock()
	for _, old := range stale {
		conn := old
		go func() { _ = conn.Close() }()
	}
	h.BroadcastUI(map[string]any{"type": "vps_list", "vps": list})
	return ac
}

func (h *Hub) UnregisterAgent(id string) {
	h.mu.Lock()
	delete(h.agents, id)
	list := h.snapshotVPSListLocked()
	h.mu.Unlock()
	h.BroadcastUI(map[string]any{"type": "vps_list", "vps": list})
}

func (h *Hub) RegisterUI(uc *UIConn) {
	h.mu.Lock()
	h.ui[uc] = struct{}{}
	list := h.snapshotVPSListLocked()
	on := h.autoRestartOn
	ar := h.autoRestartSec
	si := h.cfgScreenshotIntervalSec
	h.mu.Unlock()
	h.sendToUI(uc, map[string]any{"type": "vps_list", "vps": list})
	h.sendToUI(uc, map[string]any{
		"type":                "auto_restart_state",
		"enabled":             on,
		"interval_sec":        ar,
		"screenshot_interval": si,
	})
}

func (h *Hub) UnregisterUI(uc *UIConn) {
	h.mu.Lock()
	delete(h.ui, uc)
	h.mu.Unlock()
}

// snapshotVPSListLocked: caller must hold h.mu (Lock or RLock).
func (h *Hub) snapshotVPSListLocked() []VPSInfo {
	out := make([]VPSInfo, 0, len(h.agents))
	for _, a := range h.agents {
		vi := VPSInfo{
			ID:        a.ID,
			Hostname:  a.Hostname,
			MachineID: a.MachineID,
			LocalIP:   a.LocalIP,
			Connected: true,
			LastSeen:  time.Now().Unix(),
		}
		if a.MetricsTS > 0 {
			vi.HasMetrics = true
			vi.CpuPercent = a.CpuPercent
			vi.Cores = a.Cores
			vi.Threads = a.Threads
			vi.VoltRunning = a.VoltRunning
			vi.WebrbRunning = a.WebrbRunning
			vi.UptimeSec = a.UptimeSec
			vi.NetSentMbps = a.NetSentMbps
			vi.NetRecvMbps = a.NetRecvMbps
		} else {
			vi.VoltRunning = true
			vi.WebrbRunning = true
		}
		out = append(out, vi)
	}
	return out
}

func (h *Hub) broadcastVPSList() {
	h.mu.RLock()
	list := h.snapshotVPSListLocked()
	h.mu.RUnlock()
	h.BroadcastUI(map[string]any{"type": "vps_list", "vps": list})
}

func (h *Hub) BroadcastUI(msg any) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.RLock()
	for u := range h.ui {
		u.mu.Lock()
		_ = u.Conn.WriteMessage(websocket.TextMessage, b)
		u.mu.Unlock()
	}
	h.mu.RUnlock()
}

func (h *Hub) sendToUI(uc *UIConn, msg any) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	uc.mu.Lock()
	_ = uc.Conn.WriteMessage(websocket.TextMessage, b)
	uc.mu.Unlock()
}

func (h *Hub) SendToAgent(agentID string, cmd Command, payload map[string]any) bool {
	h.mu.RLock()
	a, ok := h.agents[agentID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	m := map[string]any{"type": "command", "cmd": string(cmd)}
	for k, v := range payload {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return false
	}
	a.mu.Lock()
	err = a.Conn.WriteMessage(websocket.TextMessage, b)
	a.mu.Unlock()
	return err == nil
}

// SendJSONToAgent writes a prepared JSON message to one agent (used for agent_rpc).
func (h *Hub) SendJSONToAgent(agentID string, msg map[string]any) bool {
	h.mu.RLock()
	a, ok := h.agents[agentID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	a.mu.Lock()
	err = a.Conn.WriteMessage(websocket.TextMessage, b)
	a.mu.Unlock()
	return err == nil
}

func (h *Hub) BroadcastCommand(cmd Command, payload map[string]any) {
	h.mu.RLock()
	ids := make([]string, 0, len(h.agents))
	for id := range h.agents {
		ids = append(ids, id)
	}
	h.mu.RUnlock()
	for _, id := range ids {
		_ = h.SendToAgent(id, cmd, payload)
	}
}

func (h *Hub) HandleAgentMessage(agentID string, raw []byte) {
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	t, _ := msg["type"].(string)
	switch t {
	case "screenshot":
		b64, _ := msg["data"].(string)
		h.BroadcastUI(map[string]any{"type": "screenshot", "vps_id": agentID, "data": b64})
	case "cookies":
		txt, _ := msg["data"].(string)
		h.BroadcastUI(map[string]any{"type": "cookies", "vps_id": agentID, "data": txt})
	case "metrics":
		h.applyAgentMetrics(agentID, msg)
	case "agent_rpc_result":
		msg["vps_id"] = agentID
		h.BroadcastUI(msg)
	case "pong", "ack":
		// no-op
	default:
		log.Printf("agent msg: %s", t)
	}
}

func numFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return 0
	}
}

func numInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	default:
		return 0
	}
}

func (h *Hub) applyAgentMetrics(agentID string, msg map[string]any) {
	h.mu.Lock()
	a, ok := h.agents[agentID]
	if !ok {
		h.mu.Unlock()
		return
	}
	a.CpuPercent = numFloat(msg["cpu_percent"])
	a.Cores = numInt(msg["cores"])
	a.Threads = numInt(msg["threads"])
	if v, ok := msg["volt_running"].(bool); ok {
		a.VoltRunning = v
	}
	if v, ok := msg["webrb_running"].(bool); ok {
		a.WebrbRunning = v
	}
	if s, ok := msg["local_ip"].(string); ok {
		a.LocalIP = s
	}
	a.UptimeSec = int64(numInt(msg["uptime_sec"]))
	a.NetSentMbps = numFloat(msg["net_sent_mbps"])
	a.NetRecvMbps = numFloat(msg["net_recv_mbps"])
	a.MetricsTS = time.Now().Unix()
	list := h.snapshotVPSListLocked()
	h.mu.Unlock()
	h.BroadcastUI(map[string]any{"type": "vps_list", "vps": list})
}

func (h *Hub) UpdateScreenshotInterval(sec int) {
	if sec < 3 {
		sec = 3
	}
	h.mu.Lock()
	h.cfgScreenshotIntervalSec = sec
	agents := make([]*AgentConn, 0, len(h.agents))
	for _, a := range h.agents {
		agents = append(agents, a)
	}
	on := h.autoRestartOn
	ar := h.autoRestartSec
	h.mu.Unlock()
	h.BroadcastUI(map[string]any{"type": "config_snapshot_interval", "seconds": sec})
	b, err := json.Marshal(map[string]any{
		"type":                    "config",
		"screenshot_interval_sec": sec,
		"auto_restart_enabled":    on,
		"auto_restart_sec":        ar,
	})
	if err != nil {
		return
	}
	for _, a := range agents {
		a.mu.Lock()
		_ = a.Conn.WriteMessage(websocket.TextMessage, b)
		a.mu.Unlock()
	}
}

func (h *Hub) ScreenshotInterval() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfgScreenshotIntervalSec
}

func (h *Hub) SetAutoRestart(enabled bool, intervalSec int) {
	h.mu.Lock()
	if intervalSec >= 60 {
		h.autoRestartSec = intervalSec
	}
	h.autoRestartOn = enabled
	if h.autoRestartStop != nil {
		close(h.autoRestartStop)
		h.autoRestartStop = nil
	}
	if enabled {
		stop := make(chan struct{})
		h.autoRestartStop = stop
		d := h.autoRestartSec
		go h.autoRestartLoop(stop, d)
	}
	si := h.cfgScreenshotIntervalSec
	is := h.autoRestartSec
	agents := make([]*AgentConn, 0, len(h.agents))
	for _, a := range h.agents {
		agents = append(agents, a)
	}
	h.mu.Unlock()
	h.BroadcastUI(map[string]any{
		"type":                "auto_restart_state",
		"enabled":             enabled,
		"interval_sec":        is,
		"screenshot_interval": si,
	})
	b, err := json.Marshal(map[string]any{
		"type":                    "config",
		"screenshot_interval_sec": si,
		"auto_restart_enabled":    enabled,
		"auto_restart_sec":        is,
	})
	if err == nil {
		for _, a := range agents {
			a.mu.Lock()
			_ = a.Conn.WriteMessage(websocket.TextMessage, b)
			a.mu.Unlock()
		}
	}
}

func (h *Hub) AutoRestartState() (bool, int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.autoRestartOn, h.autoRestartSec
}

func (h *Hub) autoRestartLoop(stop <-chan struct{}, everySec int) {
	t := time.NewTicker(time.Duration(everySec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			h.mu.RLock()
			on := h.autoRestartOn
			h.mu.RUnlock()
			if !on {
				return
			}
			h.BroadcastCommand(CmdRefreshAll, nil)
		}
	}
}

func DecodeScreenshot(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}
