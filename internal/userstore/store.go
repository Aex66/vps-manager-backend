package userstore

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

// Migrate creates tenants/users and upgrades older schemas (idempotent).
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS tenants (
	id            TEXT PRIMARY KEY,
	name          TEXT NOT NULL DEFAULT '',
	agent_secret  TEXT NOT NULL
);
`); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS users (
	id            BIGSERIAL PRIMARY KEY,
	username      TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
`); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id TEXT`); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT`); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `UPDATE users SET role = 'admin' WHERE role IS NULL OR trim(role) = ''`); err != nil {
		return err
	}
	// Platform operator accounts are not scoped to a client tenant.
	if _, err := s.pool.Exec(ctx, `
UPDATE users SET tenant_id = NULL
WHERE LOWER(TRIM(COALESCE(role, ''))) = 'admin'
`); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username));
`); err != nil {
		return err
	}
	return nil
}

func normUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Bootstrap ensures default tenant and first admin when no users exist.
func (s *Store) Bootstrap(ctx context.Context, username, plainPassword, agentSecret string) error {
	agentSecret = strings.TrimSpace(agentSecret)
	if agentSecret == "" {
		return errors.New("bootstrap: agent secret must be non-empty for default tenant")
	}
	if _, err := s.pool.Exec(ctx, `
INSERT INTO tenants (id, name, agent_secret) VALUES ('default', 'Default', $1)
ON CONFLICT (id) DO NOTHING
`, agentSecret); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `UPDATE users SET tenant_id = 'default' WHERE tenant_id IS NULL`); err != nil {
		return err
	}

	user := normUsername(username)
	if user == "" {
		return errors.New("bootstrap: empty username")
	}
	if plainPassword == "" {
		return errors.New("bootstrap: empty password (set ADMIN_PASSWORD for first user)")
	}
	var n int64
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, tenant_id, role) VALUES ($1, $2, NULL, 'admin')`,
		user, string(hash),
	)
	return err
}

// VerifyLogin returns tenant_id (empty for platform admin) and role for JWT when credentials match.
func (s *Store) VerifyLogin(ctx context.Context, username, plainPassword string) (tenantID, role string, ok bool, err error) {
	user := normUsername(username)
	if user == "" || plainPassword == "" {
		return "", "", false, nil
	}
	var hash string
	var tid, rdb *string
	qerr := s.pool.QueryRow(ctx,
		`SELECT password_hash, tenant_id, role FROM users WHERE lower(username) = $1 LIMIT 1`,
		user,
	).Scan(&hash, &tid, &rdb)
	if errors.Is(qerr, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if qerr != nil {
		return "", "", false, qerr
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword)); err != nil {
		return "", "", false, nil
	}
	rl := "user"
	if rdb != nil && strings.TrimSpace(*rdb) != "" {
		rl = strings.TrimSpace(*rdb)
	}
	rl = strings.ToLower(rl)
	if rl == "admin" {
		return "", "admin", true, nil
	}
	if rl != "user" {
		rl = "user"
	}
	outT := "default"
	if tid != nil && strings.TrimSpace(*tid) != "" {
		outT = strings.TrimSpace(*tid)
	}
	return outT, rl, true, nil
}

// ValidateAgentTenant checks secret for tenant_id (empty tenant_id → "default").
func (s *Store) ValidateAgentTenant(ctx context.Context, tenantID, secret string) (bool, error) {
	tid := strings.TrimSpace(tenantID)
	if tid == "" {
		tid = "default"
	}
	sec := strings.TrimSpace(secret)
	var stored string
	err := s.pool.QueryRow(ctx, `SELECT agent_secret FROM tenants WHERE id = $1`, tid).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// subtle.ConstantTimeCompare returns 0 immediately if lengths differ.
	return subtle.ConstantTimeCompare([]byte(sec), []byte(stored)) == 1, nil
}
