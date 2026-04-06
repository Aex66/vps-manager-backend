package userstore

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrTenantRowNotFound = errors.New("tenant not found")

var ErrTenantIDTaken = errors.New("tenant id already exists")

// TenantExists reports whether a row exists in tenants.
func (s *Store) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	tid := strings.TrimSpace(tenantID)
	if tid == "" {
		return false, nil
	}
	var one int
	err := s.pool.QueryRow(ctx, `SELECT 1 FROM tenants WHERE id = $1 LIMIT 1`, tid).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListTenants returns all tenants (ids and safe metadata).
func (s *Store) ListTenants(ctx context.Context) ([]TenantInfo, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, agent_secret FROM tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantInfo
	for rows.Next() {
		var id, name, sec string
		if err := rows.Scan(&id, &name, &sec); err != nil {
			return nil, err
		}
		out = append(out, TenantInfo{
			ID:                    strings.TrimSpace(id),
			Name:                  strings.TrimSpace(name),
			AgentSecretConfigured: strings.TrimSpace(sec) != "",
		})
	}
	return out, rows.Err()
}

// CreateTenant inserts a new tenant (id unique).
func (s *Store) CreateTenant(ctx context.Context, id, displayName, agentSecret string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("tenant id required")
	}
	sec := strings.TrimSpace(agentSecret)
	if sec == "" {
		return errors.New("agent_secret required")
	}
	name := strings.TrimSpace(displayName)
	_, err := s.pool.Exec(ctx, `
INSERT INTO tenants (id, name, agent_secret) VALUES ($1, $2, $3)
`, id, name, sec)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrTenantIDTaken
		}
		return err
	}
	return nil
}

// TenantInfo is safe to expose to tenant admins (no secret value).
type TenantInfo struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	AgentSecretConfigured bool   `json:"agent_secret_configured"`
}

func (s *Store) GetTenantInfo(ctx context.Context, tenantID string) (TenantInfo, error) {
	tid := normTenantForQuery(tenantID)
	var name, sec string
	err := s.pool.QueryRow(ctx, `SELECT name, agent_secret FROM tenants WHERE id = $1`, tid).Scan(&name, &sec)
	if errors.Is(err, pgx.ErrNoRows) {
		return TenantInfo{}, ErrTenantRowNotFound
	}
	if err != nil {
		return TenantInfo{}, err
	}
	return TenantInfo{
		ID:                    tid,
		Name:                  strings.TrimSpace(name),
		AgentSecretConfigured: strings.TrimSpace(sec) != "",
	}, nil
}

// UpdateTenantSettings updates display name and/or agent secret for a tenant row.
// Empty agent_secret string means "do not change secret". To change secret, pass non-empty trimmed value.
func (s *Store) UpdateTenantSettings(ctx context.Context, tenantID string, displayName *string, agentSecret *string) error {
	tid := normTenantForQuery(tenantID)
	var name string
	err := s.pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tid).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrTenantRowNotFound
	}
	if err != nil {
		return err
	}
	newName := strings.TrimSpace(name)
	if displayName != nil {
		newName = strings.TrimSpace(*displayName)
	}
	if agentSecret != nil {
		sec := strings.TrimSpace(*agentSecret)
		if sec == "" {
			_, err = s.pool.Exec(ctx, `UPDATE tenants SET name = $1 WHERE id = $2`, newName, tid)
			return err
		}
		_, err = s.pool.Exec(ctx, `UPDATE tenants SET name = $1, agent_secret = $2 WHERE id = $3`, newName, sec, tid)
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE tenants SET name = $1 WHERE id = $2`, newName, tid)
	return err
}
