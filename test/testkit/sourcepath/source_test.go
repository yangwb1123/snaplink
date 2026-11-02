package sourcepath

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
	"testing"
)

//go:embed source_test.go
var ownSource []byte

var initialRoot, initialError = Bind("test/testkit/sourcepath/source_test.go", ownSource)

func fixture(t *testing.T) (string, string, string, []byte) {
	t.Helper()
	root := t.TempDir()
	relative := "p/q/test.go"
	directory := filepath.Join(root, "p", "q")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	expected := []byte("package q\n")
	for name, data := range map[string][]byte{
		"go.mod": []byte("module " + modulePath + "\n"),
		relative: expected,
	} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, directory, relative, expected
}

func TestBindAcceptsExactSourceAndModule(t *testing.T) {
	root, directory, relative, expected := fixture(t)
	got, err := bindDirectory(directory, relative, expected)
	if err != nil || got != root {
		t.Fatalf("binding = %q, %v; want %q", got, err, root)
	}
}

func TestBindRejectsInvalidInput(t *testing.T) {
	_, directory, relative, expected := fixture(t)
	cases := []struct {
		name, directory, relative string
		expected                  []byte
	}{
		{"relative-directory", "p/q", relative, expected},
		{"unclean-directory", directory + string(filepath.Separator) + ".", relative, expected},
		{"empty-relative", directory, "", expected},
		{"absolute-relative", directory, "/p/q/test.go", expected},
		{"traversal", directory, "../test.go", expected},
		{"dot-segment", directory, "p/./q/test.go", expected},
		{"wrong-extension", directory, "p/q/test.txt", expected},
		{"empty-source", directory, relative, nil},
		{"wrong-package", filepath.Dir(directory), relative, expected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bindDirectory(tc.directory, tc.relative, tc.expected)
			if err == nil || got != "" {
				t.Fatalf("invalid binding accepted: %q, %v", got, err)
			}
		})
	}
}

func TestBindRejectsChangedIdentity(t *testing.T) {
	for _, mode := range []string{"module", "source", "missing-source"} {
		t.Run(mode, func(t *testing.T) {
			root, directory, relative, expected := fixture(t)
			var err error
			switch mode {
			case "module":
				err = os.WriteFile(filepath.Join(root, "go.mod"), []byte("module another/project\n"), 0o600)
			case "source":
				err = os.WriteFile(filepath.Join(root, relative), []byte("package mutated\n"), 0o600)
			default:
				err = os.Remove(filepath.Join(root, relative))
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := bindDirectory(directory, relative, expected); err == nil || got != "" {
				t.Fatalf("changed identity accepted: %q, %v", got, err)
			}
		})
	}
}

func TestBindRejectsSymlinks(t *testing.T) {
	for _, mode := range []string{"root", "source"} {
		t.Run(mode, func(t *testing.T) {
			root, directory, relative, expected := fixture(t)
			if mode == "root" {
				link := filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				directory = filepath.Join(link, "p", "q")
			} else {
				original := filepath.Join(root, relative)
				target := filepath.Join(root, "other.go")
				if err := os.Rename(original, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, original); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := bindDirectory(directory, relative, expected); err == nil || got != "" {
				t.Fatalf("symlink binding accepted: %q, %v", got, err)
			}
		})
	}
}

func TestBoundRootSurvivesCWDChange(t *testing.T) {
	if initialError != nil {
		t.Fatal(initialError)
	}
	before, err := os.ReadFile(filepath.Join(initialRoot, "test", "testkit", "sourcepath", "source_test.go"))
	if err != nil || !bytes.Equal(before, ownSource) {
		t.Fatalf("initial source mismatch: %v", err)
	}
	t.Chdir(t.TempDir())
	after, err := os.ReadFile(filepath.Join(initialRoot, "test", "testkit", "sourcepath", "source_test.go"))
	if err != nil || !bytes.Equal(after, ownSource) {
		t.Fatalf("bound source changed with cwd: %v", err)
	}
}
