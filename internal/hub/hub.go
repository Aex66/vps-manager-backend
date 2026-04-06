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

// PlatformUITenantID is the synthetic tenant id for the operator UI WebSocket (all-tenant broadcast only).
const PlatformUITenantID = "__platform__"

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
	CmdGrabDeadcookie  Command = "grab_deadcookie"
	CmdScreenshot      Command = "screenshot"
	CmdStopVPS         Command = "stop_vps"
	CmdPing            Command = "ping"
)

type VPSInfo struct {
	ID              string  `json:"id"`
	Hostname        string  `json:"hostname"`
	MachineID       string  `json:"machine_id,omitempty"`
	LocalIP         string  `json:"local_ip,omitempty"`
	Connected       bool    `json:"connected"`
	LastSeen        int64   `json:"last_seen"`
	HasMetrics      bool    `json:"has_metrics"`
	CpuPercent      float64 `json:"cpu_percent"`
	Cores           int     `json:"cores"`
	Threads         int     `json:"threads"`
	VoltRunning     bool    `json:"volt_running"`
	WebrbRunning    bool    `json:"webrb_running"`
	UptimeSec       int64   `json:"uptime_sec,omitempty"`
	NetSentMbps     float64 `json:"net_sent_mbps"`
	NetRecvMbps     float64 `json:"net_recv_mbps"`
	RobloxInstances int     `json:"roblox_instances"`
	ScreenshotB64   string  `json:"screenshot_b64,omitempty"`
	CookiesSnippet  string  `json:"cookies_snippet,omitempty"`
}

type AgentConn struct {
	ID        string
	Hostname  string
	MachineID string
	TenantID  string
	Conn      *websocket.Conn
	mu        sync.Mutex

	CpuPercent      float64
	Cores           int
	Threads         int
	VoltRunning     bool
	WebrbRunning    bool
	LocalIP         string
	UptimeSec       int64
	NetSentMbps     float64
	NetRecvMbps     float64
	RobloxInstances int
	MetricsTS       int64
}

type UIConn struct {
	Conn     *websocket.Conn
	TenantID string
	mu       sync.Mutex
}

type tenantAutoRestart struct {
	on   bool
	sec  int
	stop chan struct{}
}

type Hub struct {
	mu sync.RWMutex

	agents              map[string]*AgentConn
	ui                  map[*UIConn]struct{}
	defaultAutoRestartSec int

	autoMu       sync.Mutex
	autoByTenant map[string]*tenantAutoRestart
}

func NewHub(autoRestartDefaultSec int) *Hub {
	if autoRestartDefaultSec < 60 {
		autoRestartDefaultSec = 3600
	}
	return &Hub{
		agents:                make(map[string]*AgentConn),
		ui:                    make(map[*UIConn]struct{}),
		defaultAutoRestartSec: autoRestartDefaultSec,
		autoByTenant:          make(map[string]*tenantAutoRestart),
	}
}

func (h *Hub) tenantNorm(tid string) string {
	t := strings.TrimSpace(tid)
	if t == "" {
		return "default"
	}
	return t
}

// RegisterAgent registers an agent under a tenant; reconnect dedupe is per-tenant only.
func (h *Hub) RegisterAgent(id, hostname, machineID, tenantID string, c *websocket.Conn) *AgentConn {
	tenantID = h.tenantNorm(tenantID)
	hostKey := strings.TrimSpace(hostname)
	if hostKey == "" {
		hostKey = "unknown"
	}
	mid := strings.TrimSpace(machineID)
	h.mu.Lock()
	var stale []*websocket.Conn
	for existingID, a := range h.agents {
		if a.TenantID != tenantID {
			continue
		}
		ah := strings.TrimSpace(a.Hostname)
		am := strings.TrimSpace(a.MachineID)
		same := false
		switch {
		case mid != "":
			if strings.EqualFold(am, mid) {
				same = true
			} else if am == "" && strings.EqualFold(ah, hostKey) {
				same = true
			}
		default:
			if am == "" && strings.EqualFold(ah, hostKey) {
				same = true
			}
		}
		if same {
			delete(h.agents, existingID)
			stale = append(stale, a.Conn)
		}
	}
	ac := &AgentConn{ID: id, Hostname: hostname, MachineID: mid, TenantID: tenantID, Conn: c}
	h.agents[id] = ac
	list := h.snapshotVPSListLockedForTenant(tenantID)
	h.mu.Unlock()
	for _, old := range stale {
		conn := old
		go func() { _ = conn.Close() }()
	}
	h.BroadcastUITenant(tenantID, map[string]any{"type": "vps_list", "vps": list})
	return ac
}

func (h *Hub) UnregisterAgent(id string) {
	h.mu.Lock()
	a, ok := h.agents[id]
	if !ok {
		h.mu.Unlock()
		return
	}
	tenantID := a.TenantID
	delete(h.agents, id)
	list := h.snapshotVPSListLockedForTenant(tenantID)
	h.mu.Unlock()
	h.BroadcastUITenant(tenantID, map[string]any{"type": "vps_list", "vps": list})
}

func (h *Hub) RegisterUI(uc *UIConn) {
	if uc.TenantID != PlatformUITenantID {
		uc.TenantID = h.tenantNorm(uc.TenantID)
	}
	h.mu.Lock()
	h.ui[uc] = struct{}{}
	h.mu.Unlock()
	if uc.TenantID == PlatformUITenantID {
		h.sendToUI(uc, map[string]any{"type": "vps_list", "vps": []VPSInfo{}})
		h.sendToUI(uc, map[string]any{
			"type":         "auto_restart_state",
			"enabled":      false,
			"interval_sec": h.defaultAutoRestartSec,
		})
		return
	}
	h.mu.Lock()
	list := h.snapshotVPSListLockedForTenant(uc.TenantID)
	h.mu.Unlock()
	h.sendToUI(uc, map[string]any{"type": "vps_list", "vps": list})
	on, ar := h.AutoRestartStateForTenant(uc.TenantID)
	h.sendToUI(uc, map[string]any{
		"type":         "auto_restart_state",
		"enabled":      on,
		"interval_sec": ar,
	})
}

func (h *Hub) UnregisterUI(uc *UIConn) {
	h.mu.Lock()
	delete(h.ui, uc)
	h.mu.Unlock()
}

func (h *Hub) snapshotVPSListLockedForTenant(tenantID string) []VPSInfo {
	out := make([]VPSInfo, 0, len(h.agents))
	for _, a := range h.agents {
		if a.TenantID != tenantID {
			continue
		}
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
			vi.RobloxInstances = a.RobloxInstances
		} else {
			vi.VoltRunning = true
			vi.WebrbRunning = true
		}
		out = append(out, vi)
	}
	return out
}

func (h *Hub) broadcastVPSListTenant(tenantID string) {
	tenantID = h.tenantNorm(tenantID)
	h.mu.RLock()
	list := h.snapshotVPSListLockedForTenant(tenantID)
	h.mu.RUnlock()
	h.BroadcastUITenant(tenantID, map[string]any{"type": "vps_list", "vps": list})
}

func (h *Hub) BroadcastUITenant(tenantID string, msg any) {
	tenantID = h.tenantNorm(tenantID)
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for u := range h.ui {
		if u.TenantID != tenantID {
			continue
		}
		u.mu.Lock()
		_ = u.Conn.WriteMessage(websocket.TextMessage, b)
		u.mu.Unlock()
	}
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

// AgentTenant returns (tenantID, true) if the agent is connected.
func (h *Hub) AgentTenant(agentID string) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	a, ok := h.agents[agentID]
	if !ok {
		return "", false
	}
	return a.TenantID, true
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

func (h *Hub) BroadcastCommandTenant(tenantID string, cmd Command, payload map[string]any) {
	tenantID = h.tenantNorm(tenantID)
	h.mu.RLock()
	ids := make([]string, 0, len(h.agents))
	for id, a := range h.agents {
		if a.TenantID == tenantID {
			ids = append(ids, id)
		}
	}
	h.mu.RUnlock()
	for _, id := range ids {
		_ = h.SendToAgent(id, cmd, payload)
	}
}

func (h *Hub) BroadcastJSONToAgentsTenant(tenantID string, msg map[string]any) {
	tenantID = h.tenantNorm(tenantID)
	h.mu.RLock()
	ids := make([]string, 0, len(h.agents))
	for id, a := range h.agents {
		if a.TenantID == tenantID {
			ids = append(ids, id)
		}
	}
	h.mu.RUnlock()
	for _, id := range ids {
		_ = h.SendJSONToAgent(id, msg)
	}
}

// BroadcastJSONToAllAgents sends msg to every connected agent (all tenants), e.g. after admin uploads a bundle.
func (h *Hub) BroadcastJSONToAllAgents(msg map[string]any) {
	h.mu.RLock()
	ids := make([]string, 0, len(h.agents))
	for id := range h.agents {
		ids = append(ids, id)
	}
	h.mu.RUnlock()
	for _, id := range ids {
		_ = h.SendJSONToAgent(id, msg)
	}
}

func (h *Hub) HandleAgentMessage(agentID string, raw []byte) {
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	h.mu.RLock()
	a, ok := h.agents[agentID]
	tenantID := ""
	if ok {
		tenantID = a.TenantID
	}
	h.mu.RUnlock()
	if tenantID == "" {
		return
	}

	t, _ := msg["type"].(string)
	switch t {
	case "screenshot":
		b64, _ := msg["data"].(string)
		h.BroadcastUITenant(tenantID, map[string]any{"type": "screenshot", "vps_id": agentID, "data": b64})
	case "cookies":
		txt, _ := msg["data"].(string)
		h.BroadcastUITenant(tenantID, map[string]any{"type": "cookies", "vps_id": agentID, "data": txt})
	case "deadcookie":
		txt, _ := msg["data"].(string)
		h.BroadcastUITenant(tenantID, map[string]any{"type": "deadcookie", "vps_id": agentID, "data": txt})
	case "metrics":
		h.applyAgentMetrics(agentID, msg)
	case "agent_rpc_result":
		msg["vps_id"] = agentID
		h.BroadcastUITenant(tenantID, msg)
	case "command_rejected":
		cmd, _ := msg["cmd"].(string)
		reason, _ := msg["reason"].(string)
		h.BroadcastUITenant(tenantID, map[string]any{
			"type":   "command_rejected",
			"vps_id": agentID,
			"cmd":    cmd,
			"reason": reason,
		})
	case "pong", "ack":
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
	tid := a.TenantID
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
	a.RobloxInstances = numInt(msg["roblox_instances"])
	a.MetricsTS = time.Now().Unix()
	list := h.snapshotVPSListLockedForTenant(tid)
	h.mu.Unlock()
	h.BroadcastUITenant(tid, map[string]any{"type": "vps_list", "vps": list})
}

func (h *Hub) getOrCreateAutoLocked(tenantID string) *tenantAutoRestart {
	st, ok := h.autoByTenant[tenantID]
	if !ok {
		st = &tenantAutoRestart{sec: h.defaultAutoRestartSec}
		h.autoByTenant[tenantID] = st
	}
	return st
}

func (h *Hub) AutoRestartStateForTenant(tenantID string) (bool, int) {
	tenantID = h.tenantNorm(tenantID)
	h.autoMu.Lock()
	defer h.autoMu.Unlock()
	st, ok := h.autoByTenant[tenantID]
	if !ok {
		return false, h.defaultAutoRestartSec
	}
	return st.on, st.sec
}

func (h *Hub) SetAutoRestart(tenantID string, enabled bool, intervalSec int) {
	tenantID = h.tenantNorm(tenantID)
	h.autoMu.Lock()
	st := h.getOrCreateAutoLocked(tenantID)
	if intervalSec >= 60 {
		st.sec = intervalSec
	}
	if st.stop != nil {
		close(st.stop)
		st.stop = nil
	}
	st.on = enabled
	if enabled {
		stop := make(chan struct{})
		st.stop = stop
		sec := st.sec
		go h.autoRestartLoop(tenantID, stop, sec)
	}
	is := st.sec
	h.autoMu.Unlock()

	h.BroadcastUITenant(tenantID, map[string]any{
		"type":         "auto_restart_state",
		"enabled":      enabled,
		"interval_sec": is,
	})
	b, err := json.Marshal(map[string]any{
		"type":                 "config",
		"auto_restart_enabled": enabled,
		"auto_restart_sec":     is,
	})
	if err != nil {
		return
	}
	h.mu.RLock()
	for _, a := range h.agents {
		if a.TenantID != tenantID {
			continue
		}
		a.mu.Lock()
		_ = a.Conn.WriteMessage(websocket.TextMessage, b)
		a.mu.Unlock()
	}
	h.mu.RUnlock()
}

func (h *Hub) autoRestartLoop(tenantID string, stop <-chan struct{}, everySec int) {
	t := time.NewTicker(time.Duration(everySec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			h.autoMu.Lock()
			st := h.autoByTenant[tenantID]
			on := st != nil && st.on
			h.autoMu.Unlock()
			if !on {
				return
			}
			h.BroadcastJSONToAgentsTenant(tenantID, map[string]any{"type": "auto_restart_tick"})
		}
	}
}

func DecodeScreenshot(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}
