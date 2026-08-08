// Package generate: post-generation build verification.
package generate

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// verifyGeneratedBuild runs `go build` and then `go vet` against the
// freshly generated package so a broken template is caught HERE, at
// generation time, instead of silently handed to the operator as a
// "starting point" that doesn't compile — the failure mode this whole
// package exists to prevent (see the package doc comment in cmd.go). vet
// runs in addition to build because a template can regress into output that
// compiles but still fails static analysis (e.g. a Printf format mismatch)
// and previously only the CI test caught that, after the fact. It is the
// default behavior of `sso-ctl generate` (opt out with --skip-build-check,
// which skips BOTH commands), unlike most scaffolding tools (e.g.
// Rails/Django generators, which don't run the target's test suite after
// scaffolding): those tools scaffold into a project whose build health is
// the operator's own responsibility, but here the operator has nothing to
// compare against yet — the generated file's very first build IS the only
// signal that the template itself is sound.
//
// outputDir is a directory path relative to the current working directory
// (or absolute); go build/vet require an explicit "./" prefix to treat an
// argument as a filesystem path rather than an import path.
func verifyGeneratedBuild(outputDir string) error {
	target := outputDir
	if !filepath.IsAbs(target) && !strings.HasPrefix(target, ".") {
		target = "." + string(filepath.Separator) + target
	}

	for _, tool := range []string{"build", "vet"} {
		cmd := exec.Command("go", tool, target)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("go %s %s:\n%s", tool, outputDir, strings.TrimRight(string(out), "\n"))
		}
	}

	fmt.Printf("✓ Verified %s builds and passes vet\n", outputDir)
	return nil
}
