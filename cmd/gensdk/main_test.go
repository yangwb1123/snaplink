package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePythonOutputsKeepsConsumerFilesInSync(t *testing.T) {
	dir := t.TempDir()
	opts := cliOptions{
		outPy:        filepath.Join(dir, "docs", "client.py"),
		outPackagePy: filepath.Join(dir, "package", "client.py"),
	}
	const content = "# generated\n"
	if err := writePythonOutputs(opts, content); err != nil {
		t.Fatalf("writePythonOutputs: %v", err)
	}
	for _, path := range []string{opts.outPy, opts.outPackagePy} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != content {
			t.Errorf("%s = %q, want %q", path, got, content)
		}
	}
}

func TestWritePythonOutputsCanDisablePackageCopy(t *testing.T) {
	dir := t.TempDir()
	opts := cliOptions{outPy: filepath.Join(dir, "client.py")}
	if err := writePythonOutputs(opts, "# generated\n"); err != nil {
		t.Fatalf("writePythonOutputs: %v", err)
	}
	if _, err := os.Stat(opts.outPy); err != nil {
		t.Fatalf("generated output missing: %v", err)
	}
}
