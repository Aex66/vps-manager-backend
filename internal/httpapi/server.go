package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"github.com/vps-manager/back/internal/agentupdate"
	"github.com/vps-manager/back/internal/auth"
	"github.com/vps-manager/back/internal/cmdqueue"
	"github.com/vps-manager/back/internal/config"
	"github.com/vps-manager/back/internal/hub"
	"github.com/vps-manager/back/internal/hwfp"
	"github.com/vps-manager/back/internal/userstore"
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
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type Server struct {
	cfg     *config.Config
	hub     *hub.Hub
	bundles *agentupdate.Store
	users   *userstore.Store
	cmdQ    *cmdqueue.Store
}

func New(c *config.Config, h *hub.Hub, users *userstore.Store, cmdQ *cmdqueue.Store) *Server {
	dir := strings.TrimSpace(c.AgentUpdateDataDir)
	if dir == "" {
		dir = "/data"
	}
	return &Server{cfg: c, hub: h, bundles: agentupdate.NewStore(dir), users: users, cmdQ: cmdQ}
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
	mux.HandleFunc("/agent/version", s.handleAgentVersion)
	mux.HandleFunc("/agent/commands/claim", s.handleCommandsClaim)
	mux.HandleFunc("/agent/commands/ack", s.handleCommandsAck)
	mux.HandleFunc("/agent/update/download", s.handleAgentUpdateDownload)
	mux.HandleFunc("/api/admin/agent-bundle", s.handleAdminAgentBundle)
	mux.HandleFunc("/api/admin/users", s.handleAdminUsersRoot)
	mux.HandleFunc("/api/admin/users/", s.handleAdminUsersChild)
	mux.HandleFunc("/api/admin/tenant", s.handleAdminTenant)
	mux.HandleFunc("/api/admin/tenants", s.handleAdminTenantsRoot)
	mux.HandleFunc("/api/admin/login", s.handleAdminLogin)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/ws/agent", s.handleAgentWS)
	mux.HandleFunc("/ws/ui", s.handleUIWS)
	mux.HandleFunc("/commands/claim", s.handleCommandsClaim)
	mux.HandleFunc("/commands/ack", s.handleCommandsAck)
	// Same handlers under /api — many reverse proxies forward /api/* and /ws/* but not bare /commands/*.
	mux.HandleFunc("/api/commands/claim", s.handleCommandsClaim)
	mux.HandleFunc("/api/commands/ack", s.handleCommandsAck)
	return cors(logRequests(mux))
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
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
	if s.users == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tid, rl, ok, err := s.users.VerifyLogin(r.Context(), b.Username, b.Password)
	if err != nil {
		log.Printf("login db error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if strings.ToLower(strings.TrimSpace(rl)) == "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "use_admin_login",
			"message": "Operator accounts must use the admin sign-in URL.",
		})
		return
	}
	subject := strings.ToLower(strings.TrimSpace(b.Username))
	tok, err := auth.IssueToken(
		s.cfg.JWTSecret,
		subject,
		tid,
		rl,
		time.Duration(s.cfg.JWTExpireHours)*time.Hour,
	)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var b loginBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var subject string
	if s.users != nil {
		tid, rl, ok, err := s.users.VerifyLogin(r.Context(), b.Username, b.Password)
		if err != nil {
			log.Printf("admin login db error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if strings.ToLower(strings.TrimSpace(rl)) != "admin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "use_dashboard_login",
				"message": "This account is for the VPS dashboard, not the operator panel.",
			})
			return
		}
		if strings.TrimSpace(tid) != "" {
			log.Printf("admin login: user %q has non-empty tenant_id; clearing not applied server-side", b.Username)
		}
		subject = strings.ToLower(strings.TrimSpace(b.Username))
	} else {
		if b.Username != s.cfg.AdminUser || b.Password != s.cfg.AdminPass {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		subject = strings.TrimSpace(b.Username)
	}
	tok, err := auth.IssueToken(
		s.cfg.JWTSecret,
		subject,
		"",
		"admin",
		time.Duration(s.cfg.JWTExpireHours)*time.Hour,
	)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

// handleAgentVersion serves JSON for agent auto-update (?secret= and optional ?tenant_id=).
func (s *Server) handleAgentVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sec := r.URL.Query().Get("secret")
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = "default"
	}
	if !s.agentSecretAndTenantOK(r, sec, tenantID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if m, _ := s.bundles.ReadManifest(); m != nil && m.Version != "" && m.SHA256 != "" && s.bundles.ZipExists() {
		base := publicBaseFromRequest(r, s.cfg.PublicBaseURL)
		if base == "" {
			log.Printf("agent version: no PUBLIC_BASE_URL and could not infer host; set PUBLIC_BASE_URL on the server")
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "", "url": "", "sha256": ""})
			return
		}
		dl := base + "/agent/update/download?secret=" + url.QueryEscape(sec) + "&tenant_id=" + url.QueryEscape(tenantID)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version": m.Version,
			"url":     dl,
			"sha256":  m.SHA256,
		})
		return
	}
	hash := strings.ToLower(strings.TrimSpace(s.cfg.AgentUpdateSHA256))
	_ = json.NewEncoder(w).Encode(map[string]string{
		"version": strings.TrimSpace(s.cfg.AgentLatestVersion),
		"url":     strings.TrimSpace(s.cfg.AgentUpdateZipURL),
		"sha256":  hash,
	})
}

func (s *Server) handleAgentUpdateDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sec := r.URL.Query().Get("secret")
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = "default"
	}
	if !s.agentSecretAndTenantOK(r, sec, tenantID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	path := s.bundles.ZipPath()
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "update bundle not available", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		http.Error(w, "update bundle not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	http.ServeContent(w, r, "agent_update.zip", st.ModTime(), f)
}

func (s *Server) handleAdminAgentBundle(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminBearer(w, r) {
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.adminAgentBundlePost(w, r)
	case http.MethodGet:
		s.adminAgentBundleGet(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) adminAgentBundlePost(w http.ResponseWriter, r *http.Request) {
	const maxMem = 64 << 20
	if err := r.ParseMultipartForm(maxMem); err != nil {
		http.Error(w, "multipart parse error", http.StatusBadRequest)
		return
	}
	version := strings.TrimSpace(r.FormValue("version"))
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field `file`", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if err := s.bundles.Save(version, file); err != nil {
		log.Printf("agent bundle upload failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) adminAgentBundleGet(w http.ResponseWriter, r *http.Request) {
	path := s.bundles.ZipPath()
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "no bundle uploaded", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		http.Error(w, "no bundle uploaded", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="agent_update.zip"`)
	http.ServeContent(w, r, "agent_update.zip", st.ModTime(), f)
}

func (s *Server) requireAdminClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	claims, err := auth.ParseToken(s.cfg.JWTSecret, strings.TrimPrefix(h, p))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	if strings.ToLower(strings.TrimSpace(claims.Role)) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return claims, true
}

func (s *Server) requireAdminBearer(w http.ResponseWriter, r *http.Request) bool {
	_, ok := s.requireAdminClaims(w, r)
	return ok
}

func normTenantID(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return "default"
	}
	return t
}

func (s *Server) handleAdminTenantsRoot(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdminClaims(w, r); !ok {
		return
	}
	if s.users == nil {
		http.Error(w, "user database not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.users.ListTenants(r.Context())
		if err != nil {
			log.Printf("admin list tenants: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		var body struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			AgentSecret string `json:"agent_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := s.users.CreateTenant(r.Context(), body.ID, body.Name, body.AgentSecret); err != nil {
			if errors.Is(err, userstore.ErrTenantIDTaken) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			if strings.Contains(err.Error(), "required") {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			log.Printf("admin create tenant: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		info, err := s.users.GetTenantInfo(r.Context(), strings.TrimSpace(body.ID))
		if err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(info)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminTenant(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdminClaims(w, r); !ok {
		return
	}
	if s.users == nil {
		http.Error(w, "user database not configured", http.StatusServiceUnavailable)
		return
	}
	tid := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tid == "" {
		http.Error(w, "tenant_id query parameter required", http.StatusBadRequest)
		return
	}
	tid = normTenantID(tid)
	switch r.Method {
	case http.MethodGet:
		info, err := s.users.GetTenantInfo(r.Context(), tid)
		if err != nil {
			if errors.Is(err, userstore.ErrTenantRowNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			log.Printf("admin tenant get: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	case http.MethodPatch:
		var body struct {
			Name        *string `json:"name"`
			AgentSecret *string `json:"agent_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if body.Name == nil && body.AgentSecret == nil {
			http.Error(w, "no fields to update", http.StatusBadRequest)
			return
		}
		if err := s.users.UpdateTenantSettings(r.Context(), tid, body.Name, body.AgentSecret); err != nil {
			if errors.Is(err, userstore.ErrTenantRowNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			log.Printf("admin tenant patch: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		info, err := s.users.GetTenantInfo(r.Context(), tid)
		if err != nil {
			log.Printf("admin tenant get after patch: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminUsersRoot(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdminClaims(w, r); !ok {
		return
	}
	if s.users == nil {
		http.Error(w, "user database not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		filter := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		var (
			list []userstore.UserRecord
			err  error
		)
		if filter != "" {
			list, err = s.users.ListUsers(r.Context(), normTenantID(filter))
		} else {
			list, err = s.users.ListAllUsers(r.Context())
		}
		if err != nil {
			log.Printf("admin list users: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		var body struct {
			Username string  `json:"username"`
			Password string  `json:"password"`
			Role     string  `json:"role"`
			TenantID *string `json:"tenant_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if body.TenantID == nil || strings.TrimSpace(*body.TenantID) == "" {
			http.Error(w, "tenant_id is required for new client users", http.StatusBadRequest)
			return
		}
		storeTid := normTenantID(*body.TenantID)
		u, err := s.users.CreateUser(r.Context(), storeTid, body.Username, body.Password, body.Role)
		if err != nil {
			switch {
			case errors.Is(err, userstore.ErrUsernameTaken):
				http.Error(w, err.Error(), http.StatusConflict)
			case errors.Is(err, userstore.ErrForbiddenOperatorRole):
				http.Error(w, err.Error(), http.StatusForbidden)
			case errors.Is(err, userstore.ErrUnknownTenant):
				http.Error(w, err.Error(), http.StatusBadRequest)
			case strings.Contains(err.Error(), "required"):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				log.Printf("admin create user: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(u)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminUsersChild(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdminClaims(w, r)
	if !ok {
		return
	}
	if s.users == nil {
		http.Error(w, "user database not configured", http.StatusServiceUnavailable)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	idStr = strings.Trim(idStr, "/")
	if idStr == "" || strings.Contains(idStr, "/") {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(claims.Subject)

	switch r.Method {
	case http.MethodPatch:
		var body struct {
			Username *string `json:"username"`
			Password *string `json:"password"`
			Role     *string `json:"role"`
			TenantID *string `json:"tenant_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		u, err := s.users.UpdateUserByIDGlobal(r.Context(), id, userstore.UserPatch{
			Username: body.Username,
			Password: body.Password,
			Role:     body.Role,
			TenantID: body.TenantID,
		})
		if err != nil {
			switch {
			case errors.Is(err, userstore.ErrUserNotFound):
				http.Error(w, err.Error(), http.StatusNotFound)
			case errors.Is(err, userstore.ErrUsernameTaken):
				http.Error(w, err.Error(), http.StatusConflict)
			case errors.Is(err, userstore.ErrLastAdmin):
				http.Error(w, err.Error(), http.StatusForbidden)
			case errors.Is(err, userstore.ErrForbiddenOperatorRole):
				http.Error(w, err.Error(), http.StatusForbidden)
			case errors.Is(err, userstore.ErrUnknownTenant),
				errors.Is(err, userstore.ErrTenantRequiredForClient):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				log.Printf("admin update user: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(u)
	case http.MethodDelete:
		if err := s.users.DeleteUserByIDGlobal(r.Context(), id, subject); err != nil {
			switch {
			case errors.Is(err, userstore.ErrUserNotFound):
				http.Error(w, err.Error(), http.StatusNotFound)
			case errors.Is(err, userstore.ErrCannotDeleteSelf):
				http.Error(w, err.Error(), http.StatusForbidden)
			case errors.Is(err, userstore.ErrLastAdmin):
				http.Error(w, err.Error(), http.StatusForbidden)
			default:
				log.Printf("admin delete user: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func publicBaseFromRequest(r *http.Request, configured string) string {
	b := strings.TrimSuffix(strings.TrimSpace(configured), "/")
	if b != "" {
		return b
	}
	proto := "http"
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		proto = "https"
	} else if r.TLS != nil {
		proto = "https"
	}
	host := r.Host
	if xh := r.Header.Get("X-Forwarded-Host"); xh != "" {
		host = strings.TrimSpace(strings.Split(xh, ",")[0])
	}
	if host == "" {
		return ""
	}
	return proto + "://" + host
}

func (s *Server) agentSecretAndTenantOK(r *http.Request, secret, tenantID string) bool {
	if s.users != nil {
		ok, err := s.users.ValidateAgentTenant(r.Context(), tenantID, secret)
		if err != nil {
			log.Printf("agent tenant check: %v", err)
			return false
		}
		return ok
	}
	return secret == s.cfg.AgentSecret
}

// agentClaimJWT is issued on WebSocket connect so /commands/claim can be validated on any replica
// (in-memory hub is not shared across load-balanced processes).
type agentClaimJWT struct {
	VPS string `json:"vps"`
	QK  string `json:"qk"`
	TID string `json:"tid"`
	jwt.RegisteredClaims
}

func (s *Server) issueAgentClaimToken(vpsID, queueKey, tenantID string) (string, error) {
	sec := strings.TrimSpace(s.cfg.JWTSecret)
	if sec == "" {
		return "", fmt.Errorf("JWT_SECRET is empty")
	}
	now := time.Now()
	claims := agentClaimJWT{
		VPS: strings.TrimSpace(vpsID),
		QK:  strings.TrimSpace(queueKey),
		TID: normTenantID(tenantID),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(72 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	return tok.SignedString([]byte(sec))
}

func (s *Server) verifyAgentClaimToken(tokenStr, vpsID, queueKey, tenantID string) bool {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return false
	}
	sec := strings.TrimSpace(s.cfg.JWTSecret)
	if sec == "" {
		return false
	}
	var claims agentClaimJWT
	_, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(sec), nil
	})
	if err != nil {
		return false
	}
	return strings.TrimSpace(claims.VPS) == strings.TrimSpace(vpsID) &&
		strings.TrimSpace(claims.QK) == strings.TrimSpace(queueKey) &&
		normTenantID(claims.TID) == normTenantID(tenantID)
}

// validateCommandQueueClient checks agent secret, then either a signed claim_token (multi-replica)
// or the in-memory hub session (single-process / legacy).
func (s *Server) validateCommandQueueClient(r *http.Request, secret, tenantID, vpsSessionID, queueKey, claimToken string) bool {
	tid := normTenantID(tenantID)
	if !s.agentSecretAndTenantOK(r, secret, tid) {
		return false
	}
	if strings.TrimSpace(claimToken) != "" && s.verifyAgentClaimToken(claimToken, vpsSessionID, queueKey, tid) {
		return true
	}
	a, ok := s.hub.AgentSession(strings.TrimSpace(vpsSessionID))
	if !ok {
		return false
	}
	if hubTenantNorm(a.TenantID) != tid {
		return false
	}
	qk := strings.TrimSpace(queueKey)
	if qk == "" || qk != a.CommandQueueKey() {
		return false
	}
	return true
}

func hubTenantNorm(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return "default"
	}
	return t
}

func (s *Server) handleCommandsClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cmdQ == nil {
		http.Error(w, "command queue not configured", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Secret          string `json:"secret"`
		TenantID        string `json:"tenant_id"`
		VpsID           string `json:"vps_id"`
		CommandQueueKey string `json:"command_queue_key"`
		ClaimToken      string `json:"claim_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if !s.validateCommandQueueClient(r, body.Secret, body.TenantID, body.VpsID, body.CommandQueueKey, body.ClaimToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	res, err := s.cmdQ.Claim(r.Context(), strings.TrimSpace(body.CommandQueueKey))
	if err != nil {
		log.Printf("commands claim: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if res == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	out := map[string]any{
		"id":       res.ID,
		"cmd":      res.Cmd,
		"attempts": res.Attempts,
	}
	for k, v := range res.Extras {
		out[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleCommandsAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cmdQ == nil {
		http.Error(w, "command queue not configured", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Secret          string `json:"secret"`
		TenantID        string `json:"tenant_id"`
		VpsID           string `json:"vps_id"`
		CommandQueueKey string `json:"command_queue_key"`
		ClaimToken      string `json:"claim_token"`
		ID              string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if !s.validateCommandQueueClient(r, body.Secret, body.TenantID, body.VpsID, body.CommandQueueKey, body.ClaimToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cid := strings.TrimSpace(body.ID)
	if cid == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	err := s.cmdQ.Ack(r.Context(), strings.TrimSpace(body.CommandQueueKey), cid)
	if err != nil {
		if errors.Is(err, cmdqueue.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("commands ack: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = "default"
	}
	if !s.agentSecretAndTenantOK(r, secret, tenantID) {
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
	executor := strings.TrimSpace(r.URL.Query().Get("executor"))
	if executor == "" {
		executor = "volt"
	}
	en := hub.NormalizeAgentExecutor(executor)
	id := genAgentID()
	ac := s.hub.RegisterAgent(id, host, machineKey, tenantID, en, conn)
	if machineKey != "" {
		log.Printf("agent connected: %s tenant=%s hostname=%s fp=%.12s…", id, tenantID, host, machineKey)
	} else {
		log.Printf("agent connected: %s tenant=%s hostname=%s (no hardware profile; dedupe by hostname only)", id, tenantID, host)
	}

	on, arSec := s.hub.AutoRestartStateForTenant(tenantID)
	cfgMsg := map[string]any{
		"type":                 "config",
		"auto_restart_enabled": on,
		"auto_restart_sec":     arSec,
		"vps_id":               id,
		"command_queue_key":    ac.CommandQueueKey(),
		"reliable_commands":    s.cmdQ != nil,
	}
	if s.cmdQ != nil {
		if ct, err := s.issueAgentClaimToken(id, ac.CommandQueueKey(), tenantID); err != nil {
			log.Printf("agent claim token issue: %v", err)
		} else if ct != "" {
			cfgMsg["claim_token"] = ct
		}
	}
	if err := ac.WriteTextJSON(cfgMsg); err != nil {
		log.Printf("agent write config: %v", err)
	}

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
	claims, err := auth.ParseToken(s.cfg.JWTSecret, token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	uiTenant := claims.EffectiveTenantID()
	if auth.IsPlatformOperator(claims) {
		uiTenant = hub.PlatformUITenantID
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	uic := &hub.UIConn{Conn: conn, TenantID: uiTenant}
	s.hub.RegisterUI(uic)
	log.Printf("ui connected tenant=%s", uiTenant)

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
			s.handleUIMessage(uic, msg)
		}
	}()
}

func (s *Server) handleUIMessage(uic *hub.UIConn, raw []byte) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	t, _ := m["type"].(string)
	if uic.TenantID == hub.PlatformUITenantID {
		if t == "broadcast_agent_update" {
			s.hub.BroadcastJSONToAllAgents(map[string]any{"action": "update"})
		}
		return
	}
	tid := uic.TenantID
	if tid == "" {
		tid = "default"
	}
	switch t {
	case "run_command":
		cmd := wsString(m["cmd"])
		vpsID := wsString(m["vps_id"])
		if vpsID == "" || cmd == "" {
			log.Printf("ui run_command ignored: empty vps_id or cmd (vps_id=%q cmd=%q)", vpsID, cmd)
			return
		}
		atid, ok := s.hub.AgentTenant(vpsID)
		if !ok || atid != tid {
			log.Printf("ui run_command: vps_id=%q not in tenant %q", vpsID, tid)
			return
		}
		payload := map[string]any{}
		if v, ok := m["cmd_secret"]; ok {
			payload["cmd_secret"] = wsString(v)
		}
		if s.cmdQ != nil {
			a, ok := s.hub.AgentSession(vpsID)
			if !ok {
				log.Printf("ui run_command: session lost id=%q", vpsID)
				return
			}
			qk := a.CommandQueueKey()
			ctx := context.Background()
			dup, err := s.cmdQ.HasQueuedOrProcessingOfCmd(ctx, qk, cmd)
			if err != nil {
				log.Printf("ui run_command duplicate check: %v", err)
				return
			}
			if dup {
				s.hub.SendToUI(uic, map[string]any{
					"type":    "command_rejected",
					"vps_id":  vpsID,
					"cmd":     cmd,
					"reason":  "already_queued",
					"message": "The same command is already pending or processing for this VPS.",
				})
				return
			}
			if _, err := s.cmdQ.Enqueue(ctx, qk, cmd, payload); err != nil {
				log.Printf("ui run_command enqueue: %v", err)
				return
			}
			s.hub.NotifyNewCommand(vpsID)
		} else {
			if !s.hub.SendToAgent(vpsID, hub.Command(cmd), payload) {
				log.Printf("ui run_command: no agent id=%q (disconnected or unknown)", vpsID)
			}
		}
	case "broadcast_command":
		cmd := wsString(m["cmd"])
		if cmd == "" {
			return
		}
		payload := map[string]any{}
		if v, ok := m["cmd_secret"]; ok {
			payload["cmd_secret"] = wsString(v)
		}
		if s.cmdQ != nil {
			ctx := context.Background()
			enqueued := 0
			skippedDup := 0
			s.hub.EachAgentInTenant(tid, func(agentID string, a *hub.AgentConn) bool {
				qk := a.CommandQueueKey()
				dup, err := s.cmdQ.HasQueuedOrProcessingOfCmd(ctx, qk, cmd)
				if err != nil {
					log.Printf("broadcast_command duplicate check %s: %v", agentID, err)
					return true
				}
				if dup {
					skippedDup++
					return true
				}
				if _, err := s.cmdQ.Enqueue(ctx, qk, cmd, payload); err != nil {
					log.Printf("broadcast_command enqueue %s: %v", agentID, err)
					return true
				}
				enqueued++
				s.hub.NotifyNewCommand(agentID)
				return true
			})
			if enqueued == 0 && skippedDup > 0 {
				s.hub.SendToUI(uic, map[string]any{
					"type":    "command_rejected",
					"vps_id":  "",
					"cmd":     cmd,
					"reason":  "already_queued_fleet",
					"message": "Every connected agent already has this command queued or in progress.",
				})
			}
		} else {
			s.hub.BroadcastCommandTenant(tid, hub.Command(cmd), payload)
		}
	case "broadcast_agent_update":
		s.hub.BroadcastJSONToAgentsTenant(tid, map[string]any{"action": "update"})
	case "set_auto_restart":
		en, _ := m["enabled"].(bool)
		secf, _ := m["interval_sec"].(float64)
		sec := int(secf)
		s.hub.SetAutoRestart(tid, en, sec)
	case "watch_screenshots":
		vpsID := wsString(m["vps_id"])
		en, _ := m["enabled"].(bool)
		if !en {
			s.hub.SetWatchScreenshot(uic, "")
			break
		}
		if vpsID == "" {
			break
		}
		atid, ok := s.hub.AgentTenant(vpsID)
		if !ok || atid != tid {
			log.Printf("ui watch_screenshots: vps_id=%q not in tenant %q", vpsID, tid)
			break
		}
		s.hub.SetWatchScreenshot(uic, vpsID)
	case "webrtc_offer":
		vpsID := wsString(m["vps_id"])
		sid := wsString(m["webrtc_session_id"])
		if vpsID == "" || sid == "" {
			return
		}
		atid, ok := s.hub.AgentTenant(vpsID)
		if !ok || atid != tid {
			log.Printf("ui webrtc_offer: vps_id=%q not in tenant %q", vpsID, tid)
			return
		}
		s.hub.RegisterWebRTCSession(sid, uic, vpsID, tid)
		if !s.hub.SendJSONToAgent(vpsID, m) {
			s.hub.UnregisterWebRTCSession(sid)
			log.Printf("ui webrtc_offer: agent offline id=%q", vpsID)
		}
	case "webrtc_ice_candidate":
		vpsID := wsString(m["vps_id"])
		sid := wsString(m["webrtc_session_id"])
		if vpsID == "" || sid == "" {
			return
		}
		if !s.hub.WebRTCIceFromUIAllowed(sid, uic, vpsID, tid) {
			return
		}
		atid, ok := s.hub.AgentTenant(vpsID)
		if !ok || atid != tid {
			return
		}
		if !s.hub.SendJSONToAgent(vpsID, m) {
			log.Printf("ui webrtc_ice_candidate: send failed id=%q", vpsID)
		}
	case "webrtc_hangup":
		sid := wsString(m["webrtc_session_id"])
		vpsID := wsString(m["vps_id"])
		if sid != "" {
			s.hub.UnregisterWebRTCSession(sid)
		}
		if vpsID == "" {
			break
		}
		atid, ok := s.hub.AgentTenant(vpsID)
		if !ok || atid != tid {
			break
		}
		_ = s.hub.SendJSONToAgent(vpsID, m)
	case "agent_rpc":
		vpsID := wsString(m["vps_id"])
		reqID := wsString(m["request_id"])
		if vpsID == "" || reqID == "" {
			log.Printf("ui agent_rpc ignored: missing vps_id or request_id")
			return
		}
		atid, ok := s.hub.AgentTenant(vpsID)
		if !ok || atid != tid {
			s.hub.BroadcastUITenant(tid, map[string]any{
				"type":       "agent_rpc_result",
				"vps_id":     vpsID,
				"request_id": reqID,
				"ok":         false,
				"error":      "agent not in your tenant or offline",
			})
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
			s.hub.BroadcastUITenant(tid, map[string]any{
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
