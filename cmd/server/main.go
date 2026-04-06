package main

import (
	"context"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/vps-manager/back/internal/config"
	"github.com/vps-manager/back/internal/hub"
	"github.com/vps-manager/back/internal/httpapi"
	"github.com/vps-manager/back/internal/userstore"
)

func main() {
	// Optional: load ./.env into the process env (Go's os.Getenv does not read files).
	_ = godotenv.Load()
	cfg := config.Load()
	h := hub.NewHub(cfg.AutoRestartSec)

	var userDB *userstore.Store
	if cfg.DatabaseURL != "" {
		ctx := context.Background()
		var err error
		userDB, err = userstore.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		defer userDB.Close()
		if err := userDB.Migrate(ctx); err != nil {
			log.Fatalf("postgres migrate: %v", err)
		}
		if err := userDB.Bootstrap(ctx, cfg.AdminUser, cfg.AdminPass, cfg.AgentSecret); err != nil {
			log.Fatalf("postgres bootstrap: %v", err)
		}
		log.Printf("postgres: connected; UI login uses hashed passwords")
	} else {
		log.Printf("postgres: DATABASE_URL empty; UI login uses ADMIN_USERNAME / ADMIN_PASSWORD from env (legacy)")
	}

	api := httpapi.New(&cfg, h, userDB)

	addr := ":" + cfg.Port
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, api.Routes()); err != nil {
		log.Fatal(err)
	}
}
