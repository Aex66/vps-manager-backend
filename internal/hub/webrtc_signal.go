package hub

import (
	"strings"
	"sync"
)

type webrtcSessionEntry struct {
	ui       *UIConn
	vpsID    string
	tenantID string
}

// webRTCSignal routes webrtc_offer / ice from UI→agent and webrtc_answer / ice from agent→UI.
// Embedded in Hub; signaling payloads are forwarded verbatim (opaque JSON).
type webRTCSignal struct {
	mu       sync.RWMutex
	sessions map[string]*webrtcSessionEntry
}

// RegisterWebRTCSession records which UI connection initiated negotiation for sessionID → agent vpsID.
func (h *Hub) RegisterWebRTCSession(sessionID string, uc *UIConn, vpsID, tenantID string) {
	sessionID = strings.TrimSpace(sessionID)
	vpsID = strings.TrimSpace(vpsID)
	if sessionID == "" || uc == nil || vpsID == "" {
		return
	}
	tid := tenantID
	if strings.TrimSpace(tid) == "" {
		tid = "default"
	} else {
		tid = strings.TrimSpace(tid)
	}
	h.webrtc.mu.Lock()
	defer h.webrtc.mu.Unlock()
	h.webrtc.sessions[sessionID] = &webrtcSessionEntry{ui: uc, vpsID: vpsID, tenantID: tid}
}

// UnregisterWebRTCSession removes a pending session (e.g. hangup or failed offer).
func (h *Hub) UnregisterWebRTCSession(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	h.webrtc.mu.Lock()
	defer h.webrtc.mu.Unlock()
	delete(h.webrtc.sessions, sessionID)
}

// WebRTCIceFromUIAllowed is true if this UI session owns sessionID and targets vpsID under tenantID.
func (h *Hub) WebRTCIceFromUIAllowed(sessionID string, uc *UIConn, vpsID, tenantID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	vpsID = strings.TrimSpace(vpsID)
	if sessionID == "" || uc == nil || vpsID == "" {
		return false
	}
	tid := tenantID
	if strings.TrimSpace(tid) == "" {
		tid = "default"
	} else {
		tid = strings.TrimSpace(tid)
	}
	h.webrtc.mu.RLock()
	defer h.webrtc.mu.RUnlock()
	ent, ok := h.webrtc.sessions[sessionID]
	if !ok || ent == nil {
		return false
	}
	return ent.ui == uc && ent.vpsID == vpsID && ent.tenantID == tid
}

func (h *Hub) removeWebRTCSessionsForUI(uc *UIConn) {
	if uc == nil {
		return
	}
	h.webrtc.mu.Lock()
	defer h.webrtc.mu.Unlock()
	for sid, ent := range h.webrtc.sessions {
		if ent != nil && ent.ui == uc {
			delete(h.webrtc.sessions, sid)
		}
	}
}

func (h *Hub) removeWebRTCSessionsForAgent(agentID string) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return
	}
	h.webrtc.mu.Lock()
	defer h.webrtc.mu.Unlock()
	for sid, ent := range h.webrtc.sessions {
		if ent != nil && ent.vpsID == agentID {
			delete(h.webrtc.sessions, sid)
		}
	}
}

// ForwardWebRTCSignalToUI sends raw JSON to the UI that started sessionID. Returns false if unknown session.
func (h *Hub) ForwardWebRTCSignalToUI(sessionID string, raw []byte) bool {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false
	}
	h.webrtc.mu.RLock()
	ent, ok := h.webrtc.sessions[sessionID]
	var uc *UIConn
	if ok && ent != nil {
		uc = ent.ui
	}
	h.webrtc.mu.RUnlock()
	if uc == nil {
		return false
	}
	h.sendRawToUI(uc, raw)
	return true
}
