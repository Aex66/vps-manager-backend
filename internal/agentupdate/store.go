package agentupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	zipPartial      = "agent_update.zip.partial"
	manifestPartial = "agent_update_manifest.json.partial"
)

// MaxBundleSize caps the uploaded agent zip (200 MiB).
const MaxBundleSize int64 = 200 << 20

// Manifest is stored beside the zip on the persistent volume.
type Manifest struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Store reads/writes agent_update.zip and agent_update_manifest.json under dir.
type Store struct {
	dir string
}

func NewStore(dir string) *Store {
	return &Store{dir: filepath.Clean(dir)}
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) ZipPath() string {
	return filepath.Join(s.dir, "agent_update.zip")
}

func (s *Store) manifestPath() string {
	return filepath.Join(s.dir, "agent_update_manifest.json")
}

// ReadManifest returns nil, nil if no manifest file exists.
func (s *Store) ReadManifest() (*Manifest, error) {
	b, err := os.ReadFile(s.manifestPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m.Version = strings.TrimSpace(m.Version)
	m.SHA256 = strings.ToLower(strings.TrimSpace(m.SHA256))
	return &m, nil
}

// ZipExists reports whether a non-empty agent_update.zip is present.
func (s *Store) ZipExists() bool {
	st, err := os.Stat(s.ZipPath())
	return err == nil && !st.IsDir() && st.Size() > 0
}

// Save writes the zip (streaming), computes SHA-256, and updates the manifest atomically.
func (s *Store) Save(version string, r io.Reader) error {
	version = strings.TrimSpace(version)
	if version == "" {
		return errors.New("version required")
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}

	tmpZip := filepath.Join(s.dir, zipPartial)
	f, err := os.Create(tmpZip)
	if err != nil {
		return fmt.Errorf("create temp zip: %w", err)
	}
	h := sha256.New()
	lr := io.LimitReader(r, MaxBundleSize+1)
	n, err := io.Copy(io.MultiWriter(f, h), lr)
	if err != nil {
		f.Close()
		_ = os.Remove(tmpZip)
		return err
	}
	if n > MaxBundleSize {
		f.Close()
		_ = os.Remove(tmpZip)
		return fmt.Errorf("bundle exceeds max size (%d bytes)", MaxBundleSize)
	}
	if n == 0 {
		f.Close()
		_ = os.Remove(tmpZip)
		return errors.New("empty file")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpZip)
		return err
	}

	finalZip := s.ZipPath()
	_ = os.Remove(finalZip)
	if err := os.Rename(tmpZip, finalZip); err != nil {
		_ = os.Remove(tmpZip)
		return fmt.Errorf("finalize zip: %w", err)
	}

	hash := hex.EncodeToString(h.Sum(nil))
	m := Manifest{Version: version, SHA256: hash}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmpM := filepath.Join(s.dir, manifestPartial)
	if err := os.WriteFile(tmpM, append(mj, '\n'), 0o644); err != nil {
		return err
	}
	_ = os.Remove(s.manifestPath())
	if err := os.Rename(tmpM, s.manifestPath()); err != nil {
		return fmt.Errorf("finalize manifest: %w", err)
	}
	return nil
}
