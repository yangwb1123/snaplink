package config

import (
	"context"
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

// FileSource reads a YAML config file from disk. Use it as the lowest
// or middle priority Source in a Loader chain (operators typically
// want file < env < flag).
//
// Optional reports whether a missing file is OK. With Optional=true,
// the source returns (nil, nil) when the file doesn't exist — useful
// for the "drop a file at /etc/sso/local.yaml to override" pattern
// where the override file may or may not be present.
type FileSource struct {
	Path     string
	Optional bool
}

// NewFileSource is a small convenience constructor for the common case.
func NewFileSource(path string) *FileSource {
	return &FileSource{Path: path}
}

// Name returns "file:<path>".
func (s *FileSource) Name() string {
	return "file:" + s.Path
}

// Load reads the YAML file and unmarshals it into a generic map. Type
// coercion (string → time.Duration, etc.) doesn't happen here — that's
// the Loader's job when it re-marshals the merged map into *Config.
func (s *FileSource) Load(_ context.Context) (map[string]any, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if s.Optional && os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.Path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	out := map[string]any{}
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.Path, err)
	}
	return out, nil
}
