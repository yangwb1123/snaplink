package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type FileStore struct {
	mu      sync.Mutex
	baseDir string
}

func NewFileStore(baseDir string) (*FileStore, error) {
	if strings.TrimSpace(baseDir) == "" {
		return nil, errors.New("operations: base directory required")
	}
	absolute, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("operations: absolute path: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("operations: create directory: %w", err)
	}
	return &FileStore{baseDir: absolute}, nil
}

func (s *FileStore) Create(_ context.Context, operation Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := s.path(operation.ID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return errors.New("operations: duplicate id")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return s.write(path, operation)
}

func (s *FileStore) Update(_ context.Context, operation Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := s.path(operation.ID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return s.write(path, operation)
}

func (s *FileStore) Get(_ context.Context, id string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := s.path(id)
	if err != nil {
		return Operation{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, err
	}
	var operation Operation
	if err := json.Unmarshal(data, &operation); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func (s *FileStore) List(_ context.Context) ([]Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, err
	}
	out := make([]Operation, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.baseDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var operation Operation
		if err := json.Unmarshal(data, &operation); err != nil {
			return nil, err
		}
		out = append(out, operation)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *FileStore) path(id string) (string, error) {
	if !strings.HasPrefix(id, "op_") || strings.ContainsAny(id, `/\`) {
		return "", errors.New("operations: invalid id")
	}
	return filepath.Join(s.baseDir, id+".json"), nil
}

func (s *FileStore) write(path string, operation Operation) error {
	data, err := json.MarshalIndent(operation, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(s.baseDir, ".operation-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}
