// Package hwfp computes stable server-side fingerprints from raw hardware profile JSON.
package hwfp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	maxHWJSONLen  = 4096
	maxPartRunes  = 256
	partDelimiter = '|'
)

// Field order must match the agent JSON keys and stay stable.
var fieldOrder = []string{"bios_uuid", "board_serial", "disk_serial", "machine_guid"}

// Fingerprint joins normalized parts in a fixed order, appends pepper, returns SHA-256 hex.
func Fingerprint(pepper string, parts map[string]string) string {
	var b strings.Builder
	for _, k := range fieldOrder {
		v := "unknown"
		if parts != nil {
			if s, ok := parts[k]; ok && strings.TrimSpace(s) != "" {
				v = strings.TrimSpace(s)
			}
		}
		b.WriteString(strings.ToLower(v))
		b.WriteByte(partDelimiter)
	}
	sum := sha256.Sum256([]byte(b.String() + pepper))
	return hex.EncodeToString(sum[:])
}

// FromJSON decodes agent `hw` query JSON, validates, and returns the fingerprint.
func FromJSON(pepper, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > maxHWJSONLen {
		return "", fmt.Errorf("hw JSON too large")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", err
	}
	parts := make(map[string]string)
	for _, k := range fieldOrder {
		rawVal, ok := m[k]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(rawVal, &s); err != nil {
			return "", fmt.Errorf("hw %q: %w", k, err)
		}
		s = strings.TrimSpace(s)
		if len([]rune(s)) > maxPartRunes {
			s = string([]rune(s)[:maxPartRunes])
		}
		parts[k] = s
	}
	return Fingerprint(pepper, parts), nil
}

// FromLegacyMachineGUID builds the same pipe layout when only MachineGuid was sent (old agents).
func FromLegacyMachineGUID(pepper, guid string) string {
	guid = strings.TrimSpace(guid)
	if guid == "" || strings.EqualFold(guid, "unknown") {
		return ""
	}
	return Fingerprint(pepper, map[string]string{
		"machine_guid": guid,
	})
}
