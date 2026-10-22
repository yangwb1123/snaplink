// Package sourcepath binds test fixtures to the compiling test's source tree.
package sourcepath

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const modulePath = "github.com/yangwb1123/snaplink"

// Bind is called during test package initialization, before tests change cwd.
// embedded must contain the calling file's exact bytes, normally via go:embed.
// Absolute caller paths preserve standalone untrimmed test-binary behavior;
// trimmed callers bind only to the Go test tool's initial package directory.
func Bind(relative string, embedded []byte) (string, error) {
	_, caller, _, ok := runtime.Caller(1)
	if !ok {
		return "", fmt.Errorf("test source caller unavailable")
	}
	directory := filepath.Dir(caller)
	if !filepath.IsAbs(caller) {
		if filepath.ToSlash(caller) != modulePath+"/"+relative {
			return "", fmt.Errorf("unexpected trimmed test source %q", caller)
		}
		var err error
		directory, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("initial test directory: %w", err)
		}
	}
	return bindDirectory(directory, relative, embedded)
}

func bindDirectory(directory, relative string, embedded []byte) (string, error) {
	root, err := packageRoot(directory, relative, embedded)
	if err != nil {
		return "", err
	}
	if err := verifyBoundSource(root, relative, embedded); err != nil {
		return "", err
	}
	return root, nil
}

func packageRoot(directory, relative string, embedded []byte) (string, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		!fs.ValidPath(relative) || filepath.Ext(relative) != ".go" || len(embedded) == 0 {
		return "", fmt.Errorf("invalid test source binding input")
	}
	packagePath := filepath.Dir(filepath.FromSlash(relative))
	root := directory
	if packagePath != "." {
		for range strings.Split(packagePath, string(filepath.Separator)) {
			root = filepath.Dir(root)
		}
	}
	if filepath.Join(root, packagePath) != directory {
		return "", fmt.Errorf("test package directory mismatch")
	}
	return root, nil
}

func verifyBoundSource(root, relative string, embedded []byte) error {
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || canonical != root {
		return fmt.Errorf("noncanonical test source root")
	}
	source := filepath.Join(root, filepath.FromSlash(relative))
	canonical, err = filepath.EvalSymlinks(source)
	if err != nil || canonical != source {
		return fmt.Errorf("noncanonical test source file")
	}
	actual, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(actual, embedded) {
		return fmt.Errorf("compiled and on-disk test source differ")
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || strings.TrimSpace(strings.SplitN(string(mod), "\n", 2)[0]) != "module "+modulePath {
		return fmt.Errorf("test source module mismatch")
	}
	return nil
}
