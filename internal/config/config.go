package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port           string
	JWTSecret      string
	AgentSecret    string
	SecretPepper   string // server-only; mixed into agent hardware fingerprint hash
	// Agent auto-update (optional): advertised latest build + signed-off zip URL + SHA-256.
	AgentLatestVersion string
	AgentUpdateZipURL  string
	AgentUpdateSHA256  string
	AdminUser          string
	AdminPass          string
	AutoRestartSec     int
	// JWT lifetime for UI sessions (hours). Default 720h (30d). Set JWT_EXPIRE_HOURS to override.
	JWTExpireHours int
	// Persistent dir for uploaded agent zip + manifest (e.g. Railway volume /data).
	AgentUpdateDataDir string
	// Public origin for building agent download URLs (e.g. https://yourapp.up.railway.app). Optional if X-Forwarded-* is correct.
	PublicBaseURL string
	// When set (e.g. postgres://user:pass@host:5432/dbname?sslmode=disable), UI login uses users table + bcrypt.
	// If empty, login falls back to ADMIN_USERNAME / ADMIN_PASSWORD in env (legacy).
	DatabaseURL string
}

func Load() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	ar := 3600
	if v := os.Getenv("AUTO_RESTART_DEFAULT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ar = n
		}
	}
	jwtH := 720
	if v := os.Getenv("JWT_EXPIRE_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			jwtH = n
		}
	}
	dataDir := strings.TrimSpace(os.Getenv("RAILWAY_VOLUME_MOUNT_PATH"))
	if dataDir == "" {
		dataDir = getenv("AGENT_UPDATE_DATA_DIR", "/data")
	}
	return Config{
		Port:               port,
		DatabaseURL:        strings.TrimSpace(os.Getenv("DATABASE_URL")),
		JWTSecret:          getenv("JWT_SECRET", "jwt-secret-1488"),
		AgentSecret:        getenv("AGENT_SECRET", "agent-secret-1488"),
		SecretPepper:       os.Getenv("SECRET_PEPPER"),
		AgentLatestVersion: os.Getenv("AGENT_LATEST_VERSION"),
		AgentUpdateZipURL:  os.Getenv("AGENT_UPDATE_ZIP_URL"),
		AgentUpdateSHA256:  os.Getenv("AGENT_UPDATE_SHA256"),
		AgentUpdateDataDir: dataDir,
		PublicBaseURL:      strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")),
		AdminUser:          getenv("ADMIN_USERNAME", "admin"),
		AdminPass:          getenv("ADMIN_PASSWORD", "13579114"),
		AutoRestartSec:     ar,
		JWTExpireHours:     jwtH,
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
