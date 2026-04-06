package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Role     string `json:"role"`
	TenantID string `json:"tenant_id,omitempty"`
	jwt.RegisteredClaims
}

// EffectiveTenantID returns tenant_id claim or "default" for dashboard (client) tokens.
func (c *Claims) EffectiveTenantID() string {
	t := strings.TrimSpace(c.TenantID)
	if t == "" {
		return "default"
	}
	return t
}

// IsPlatformOperator is true for the global operator: role admin and no tenant in the token.
func IsPlatformOperator(c *Claims) bool {
	if c == nil {
		return false
	}
	return strings.ToLower(strings.TrimSpace(c.Role)) == "admin" && strings.TrimSpace(c.TenantID) == ""
}

func IssueToken(secret, subject, tenantID, role string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	rl := strings.TrimSpace(strings.ToLower(role))
	if rl == "" {
		rl = "user"
	}
	var tid string
	if rl == "admin" {
		tid = ""
	} else {
		tid = strings.TrimSpace(tenantID)
		if tid == "" {
			tid = "default"
		}
	}
	claims := Claims{
		Role:     rl,
		TenantID: tid,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(secret))
}

func ParseToken(secret, tokenStr string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
