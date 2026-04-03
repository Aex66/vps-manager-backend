package main

import (
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/vps-manager/back/internal/config"
	"github.com/vps-manager/back/internal/hub"
	"github.com/vps-manager/back/internal/httpapi"
)

func main() {
	// Optional: load ./.env into the process env (Go's os.Getenv does not read files).
	_ = godotenv.Load()
	cfg := config.Load()
	h := hub.NewHub(cfg.AutoRestartSec)
	api := httpapi.New(&cfg, h)

	addr := ":" + cfg.Port
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, api.Routes()); err != nil {
		log.Fatal(err)
	}
}
