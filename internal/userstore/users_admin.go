package userstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound              = errors.New("user not found")
	ErrUsernameTaken             = errors.New("username already taken")
	ErrCannotDeleteSelf          = errors.New("cannot delete your own account")
	ErrLastAdmin             = errors.New("cannot remove or demote the platform operator account")
	ErrForbiddenOperatorRole = errors.New("role admin is reserved for the platform operator account")
	ErrTenantRequiredForClient   = errors.New("client users must belong to a tenant")
	ErrUnknownTenant = errors.New("tenant does not exist")
)

// UserRecord is a tenant-scoped user without credentials.
type UserRecord struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	TenantID  string    `json:"tenant_id"`
	CreatedAt time.Time `json:"created_at"`
}

func normTenantForQuery(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return "default"
	}
	return t
}

func normRoleDB(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	if r == "admin" {
		return "admin"
	}
	return "user"
}

func isAdminRole(r string) bool {
	return normRoleDB(r) == "admin"
}

// ListUsers returns client (role user) accounts for a tenant.
func (s *Store) ListUsers(ctx context.Context, tenantID string) ([]UserRecord, error) {
	tid := normTenantForQuery(tenantID)
	rows, err := s.pool.Query(ctx, `
SELECT id, username, COALESCE(NULLIF(TRIM(role), ''), 'user'), created_at,
       COALESCE(NULLIF(TRIM(tenant_id), ''), 'default')
FROM users
WHERE COALESCE(NULLIF(TRIM(tenant_id), ''), 'default') = $1
  AND LOWER(TRIM(COALESCE(role, ''))) = 'user'
ORDER BY lower(username)
`, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRecord
	for rows.Next() {
		var u UserRecord
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &u.TenantID); err != nil {
			return nil, err
		}
		u.Role = normRoleDB(u.Role)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ListAllUsers returns every account (operator + all clients) for the platform admin UI.
func (s *Store) ListAllUsers(ctx context.Context) ([]UserRecord, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, username, COALESCE(NULLIF(TRIM(role), ''), 'user'), created_at, tenant_id
FROM users
ORDER BY LOWER(TRIM(COALESCE(role, ''))) DESC, COALESCE(tenant_id, ''), lower(username)
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRecord
	for rows.Next() {
		var u UserRecord
		var tid sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &tid); err != nil {
			return nil, err
		}
		u.Role = normRoleDB(u.Role)
		if tid.Valid && strings.TrimSpace(tid.String) != "" {
			u.TenantID = strings.TrimSpace(tid.String)
		} else {
			u.TenantID = ""
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CreateUser adds a client user to a tenant (role must not be admin).
func (s *Store) CreateUser(ctx context.Context, tenantID, username, plainPassword, role string) (UserRecord, error) {
	user := normUsername(username)
	if user == "" || plainPassword == "" {
		return UserRecord{}, errors.New("username and password required")
	}
	rl := normRoleDB(role)
	if isAdminRole(rl) {
		return UserRecord{}, ErrForbiddenOperatorRole
	}
	tid := normTenantForQuery(tenantID)
	ok, err := s.TenantExists(ctx, tid)
	if err != nil {
		return UserRecord{}, err
	}
	if !ok {
		return UserRecord{}, ErrUnknownTenant
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return UserRecord{}, err
	}
	var u UserRecord
	err = s.pool.QueryRow(ctx, `
INSERT INTO users (username, password_hash, tenant_id, role)
VALUES ($1, $2, $3, $4)
RETURNING id, username, COALESCE(NULLIF(TRIM(role), ''), 'user'), created_at,
          COALESCE(NULLIF(TRIM(tenant_id), ''), 'default')
`, user, string(hash), tid, rl).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &u.TenantID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return UserRecord{}, ErrUsernameTaken
		}
		return UserRecord{}, err
	}
	u.Role = normRoleDB(u.Role)
	return u, nil
}

func (s *Store) getUserGlobal(ctx context.Context, id int64) (UserRecord, error) {
	var u UserRecord
	var tid sql.NullString
	err := s.pool.QueryRow(ctx, `
SELECT id, username, COALESCE(NULLIF(TRIM(role), ''), 'user'), created_at, tenant_id
FROM users WHERE id = $1
`, id).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &tid)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserRecord{}, ErrUserNotFound
	}
	if err != nil {
		return UserRecord{}, err
	}
	u.Role = normRoleDB(u.Role)
	if tid.Valid && strings.TrimSpace(tid.String) != "" {
		u.TenantID = strings.TrimSpace(tid.String)
	} else {
		u.TenantID = ""
	}
	return u, nil
}

func (s *Store) countGlobalAdminsExcluding(ctx context.Context, excludeUserID int64) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `
SELECT COUNT(*) FROM users
WHERE LOWER(TRIM(COALESCE(role, ''))) = 'admin' AND id <> $1
`, excludeUserID).Scan(&n)
	return n, err
}

// UserPatch updates a user. Nil fields are left unchanged. Non-empty Password replaces the hash.
type UserPatch struct {
	Username *string
	Password *string
	Role     *string
	TenantID *string
}

// UpdateUserByIDGlobal applies a patch for the platform operator (any user id).
func (s *Store) UpdateUserByIDGlobal(ctx context.Context, id int64, patch UserPatch) (UserRecord, error) {
	u, err := s.getUserGlobal(ctx, id)
	if err != nil {
		return UserRecord{}, err
	}
	newUsername := u.Username
	if patch.Username != nil {
		nu := normUsername(*patch.Username)
		if nu == "" {
			return UserRecord{}, errors.New("username cannot be empty")
		}
		newUsername = nu
	}
	newTid := u.TenantID
	if patch.TenantID != nil {
		newTid = strings.TrimSpace(*patch.TenantID)
	}

	var dbTenant any
	var newRole string

	if isAdminRole(u.Role) {
		if patch.TenantID != nil {
			return UserRecord{}, errors.New("platform operator account has no tenant_id")
		}
		if patch.Role != nil && normRoleDB(*patch.Role) != "admin" {
			return UserRecord{}, ErrLastAdmin
		}
		newRole = "admin"
		dbTenant = nil
	} else {
		newRole = u.Role
		if patch.Role != nil {
			newRole = normRoleDB(*patch.Role)
			if isAdminRole(newRole) {
				return UserRecord{}, ErrForbiddenOperatorRole
			}
		}
		if newTid == "" {
			return UserRecord{}, ErrTenantRequiredForClient
		}
		ok, err := s.TenantExists(ctx, normTenantForQuery(newTid))
		if err != nil {
			return UserRecord{}, err
		}
		if !ok {
			return UserRecord{}, ErrUnknownTenant
		}
		dbTenant = normTenantForQuery(newTid)
	}

	if newUsername != u.Username {
		var other int64
		qerr := s.pool.QueryRow(ctx, `
SELECT id FROM users WHERE lower(username) = $1 AND id <> $2 LIMIT 1
`, newUsername, id).Scan(&other)
		if qerr == nil {
			return UserRecord{}, ErrUsernameTaken
		}
		if !errors.Is(qerr, pgx.ErrNoRows) {
			return UserRecord{}, qerr
		}
	}
	updateHash := patch.Password != nil && strings.TrimSpace(*patch.Password) != ""
	var hash []byte
	if updateHash {
		hash, err = bcrypt.GenerateFromPassword([]byte(strings.TrimSpace(*patch.Password)), bcrypt.DefaultCost)
		if err != nil {
			return UserRecord{}, err
		}
	}
	if updateHash {
		_, err = s.pool.Exec(ctx, `
UPDATE users SET username = $1, role = $2, tenant_id = $3, password_hash = $4 WHERE id = $5
`, newUsername, newRole, dbTenant, string(hash), id)
	} else {
		_, err = s.pool.Exec(ctx, `
UPDATE users SET username = $1, role = $2, tenant_id = $3 WHERE id = $4
`, newUsername, newRole, dbTenant, id)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return UserRecord{}, ErrUsernameTaken
		}
		return UserRecord{}, err
	}
	return s.getUserGlobal(ctx, id)
}

// DeleteUserByIDGlobal removes a user by id. callerSubject is the operator username (cannot delete own row).
func (s *Store) DeleteUserByIDGlobal(ctx context.Context, id int64, callerSubject string) error {
	u, err := s.getUserGlobal(ctx, id)
	if err != nil {
		return err
	}
	caller := normUsername(callerSubject)
	if caller != "" && u.Username == caller {
		return ErrCannotDeleteSelf
	}
	if isAdminRole(u.Role) {
		n, err := s.countGlobalAdminsExcluding(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrLastAdmin
		}
	}
	ct, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}
