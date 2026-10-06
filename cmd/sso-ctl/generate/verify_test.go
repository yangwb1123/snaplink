package generate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func verificationPackage(t *testing.T) string {
	t.Helper()
	module := t.TempDir()
	newBuildableModule(t, module, repoRoot(t))
	directory := filepath.Join(module, "gen", "fixture")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "fixture.go"), []byte("package fixture\n\nfunc Value() int { return 42 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestVerifyGeneratedBuildUsesOutputModuleWithoutChangingCWD(t *testing.T) {
	t.Parallel()
	directory := verificationPackage(t)
	before, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGeneratedBuild(directory); err != nil {
		t.Fatalf("standalone output module rejected: %v", err)
	}
	after, err := os.Getwd()
	if err != nil || after != before {
		t.Fatalf("verification changed cwd: before=%q after=%q err=%v", before, after, err)
	}
}

func TestVerifyGeneratedBuildAcceptsSymlinkedOutputModule(t *testing.T) {
	t.Parallel()
	directory := verificationPackage(t)
	module := filepath.Dir(filepath.Dir(directory))
	alias := filepath.Join(t.TempDir(), "module-alias")
	if err := os.Symlink(module, alias); err != nil {
		t.Fatal(err)
	}
	if err := verifyGeneratedBuild(filepath.Join(alias, "gen", "fixture")); err != nil {
		t.Fatalf("symlinked output module rejected: %v", err)
	}
}

func TestVerifyGeneratedBuildStillRejectsBuildAndVetErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, source, tool string
	}{
		{"build", "package fixture\n\nfunc Broken( {\n", "go build"},
		{"vet", "package fixture\n\nimport \"fmt\"\n\nfunc Bad() { fmt.Printf(\"%d\", \"wrong\") }\n", "go vet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := verificationPackage(t)
			if err := os.WriteFile(filepath.Join(directory, "bad.go"), []byte(tc.source), 0o644); err != nil {
				t.Fatal(err)
			}
			err := verifyGeneratedBuild(directory)
			if err == nil || !strings.Contains(err.Error(), tc.tool) {
				t.Fatalf("verification error=%v, want %s failure", err, tc.tool)
			}
		})
	}
}

func TestBuildableModulePreservesSelectedRequirementsAndQuotedReplacement(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "root with spaces")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	original := "module example.org/root\n\ngo 1.26.1\n\nrequire example.org/dependency v1.2.3 // indirect\n"
	for name, content := range map[string]string{"go.mod": original, "go.sum": "selected checksums\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	directory := t.TempDir()
	newBuildableModule(t, directory, root)
	data, err := os.ReadFile(filepath.Join(directory, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	expected := strings.Replace(original, "module example.org/root", "module scaffoldbuildtest", 1) +
		"\nrequire example.org/root v0.0.0-00010101000000-000000000000\n" +
		"replace example.org/root => " + strconv.Quote(root) + "\n"
	if string(data) != expected {
		t.Fatalf("isolated module lost root requirements or replacement: %s", data)
	}
	sum, err := os.ReadFile(filepath.Join(directory, "go.sum"))
	if err != nil || string(sum) != "selected checksums\n" {
		t.Fatalf("isolated checksum snapshot = %q, err=%v", sum, err)
	}
}
