package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port           string
	JWTSecret      string
	AgentSecret    string
	SecretPepper   string // server-only; mixed into agent hardware fingerprint hash
	AdminUser      string
	AdminPass      string
	ScreenshotHz   int
	AutoRestartSec int
}

func Load() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	shz := 5
	if v := os.Getenv("SCREENSHOT_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			shz = n
		}
	}
	ar := 3600
	if v := os.Getenv("AUTO_RESTART_DEFAULT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ar = n
		}
	}
	return Config{
		Port:           port,
		JWTSecret:      getenv("JWT_SECRET", "jwt-secret-1488"),
		AgentSecret:    getenv("AGENT_SECRET", "agent-secret-1488"),
		SecretPepper:   os.Getenv("SECRET_PEPPER"),
		AdminUser:      getenv("ADMIN_USERNAME", "admin"),
		AdminPass:      getenv("ADMIN_PASSWORD", "13579114"),
		ScreenshotHz:   shz,
		AutoRestartSec: ar,
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
