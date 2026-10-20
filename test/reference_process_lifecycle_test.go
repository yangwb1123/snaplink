package ssotest

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

const refProcessProbeEnv = "SNAPLINK_REFERENCE_PROCESS_EXIT_PROBE"

func TestReferenceProcessExitProbe(t *testing.T) {
	switch os.Getenv(refProcessProbeEnv) {
	case "fail":
		t.Fatal("controlled reference lifecycle probe failure")
	case "panic":
		panic("controlled reference lifecycle probe panic")
	case "kill":
		process, err := os.FindProcess(os.Getpid())
		refProcessCheck(t, err, "find lifecycle probe process")
		refProcessCheck(t, process.Kill(), "kill lifecycle probe process")
	}
}

func TestReferenceProcessExitClassification(t *testing.T) {
	bin, err := os.Executable()
	refProcessCheck(t, err, "find lifecycle probe executable")
	for _, mode := range []string{"", "fail", "panic", "kill"} {
		t.Run("mode-"+mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "-test.run=^TestReferenceProcessExitProbe$", "-test.timeout=10s", "-test.v")
			cmd.Env = append(os.Environ(), refProcessProbeEnv+"="+mode)
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil || (mode == "" && err != nil) || (mode != "" && err == nil) {
				t.Fatal("controlled child exit probe did not produce its requested outcome")
			}
			wantKill := mode == "kill" && runtime.GOOS != "windows"
			if refProcessWasKilled(nil, cmd.ProcessState) != wantKill {
				t.Fatal("failed/panicking child exit was confused with intentional SIGKILL")
			}
			if refProcessWasKilled(errors.New("kill refused"), cmd.ProcessState) || refProcessWasKilled(nil, nil) {
				t.Fatal("missing state or failed kill accepted as crash evidence")
			}
			wantBadLog := mode == "fail" || mode == "panic"
			if refProcessBadDiagnostics(string(output)) != wantBadLog {
				t.Fatal("child diagnostic classifier hid a panic/failure or rejected a normal exit")
			}
		})
	}
	if !refProcessBadDiagnostics("WARNING: DATA RACE") {
		t.Fatal("child race evidence was ignored")
	}
}

func TestReferenceProcessReapGuard(t *testing.T) {
	h := &referenceProcesses{}
	if !h.allReaped() {
		t.Fatal("empty process set blocks schema cleanup")
	}
	first, second := &refProcess{done: make(chan struct{})}, &refProcess{done: make(chan struct{})}
	h.children = []*refProcess{first, second}
	if h.allReaped() {
		t.Fatal("schema cleanup allowed with running/unreaped processes")
	}
	close(first.done)
	if h.allReaped() {
		t.Fatal("one reaped child incorrectly authorizes shared-schema deletion")
	}
	close(second.done)
	if !h.allReaped() {
		t.Fatal("all wait completions failed to authorize schema cleanup")
	}
}
