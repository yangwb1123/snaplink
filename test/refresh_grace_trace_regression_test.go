package ssotest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/internal/handler/tokengrant"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	inflightTraceChildEnv = "SNAPLINK_INFLIGHT_TRACE_CHILD"
	inflightTracePrefix   = "refresh_phase_trace"
	inflightTraceFailure  = "controlled inflight diagnostic failure"
)

type inflightTraceOutput struct {
	mu        sync.Mutex
	data      bytes.Buffer
	truncated bool
}

func (o *inflightTraceOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	remaining := 256*1024 - o.data.Len()
	if len(p) > remaining {
		o.truncated = true
		_, _ = o.data.Write(p[:remaining])
	} else {
		_, _ = o.data.Write(p)
	}
	return len(p), nil
}

func runInflightTraceChild(t *testing.T, fail bool) {
	t.Helper()
	first, _, _, issuer := newInflightServers(t, tokengrant.NewRefreshGraceCache(time.Minute))
	var once sync.Once
	release := func() {
		once.Do(func() {
			close(issuer.release)
			fmt.Println("inflight trace child release confirmed")
		})
	}
	result := make(chan inflightResponse, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		release()
		select {
		case <-done:
			fmt.Println("inflight trace child request joined")
		case <-time.After(5 * time.Second):
			t.Error("inflight trace child join failed")
		}
	})
	go func() {
		defer close(done)
		result <- postInflightRefresh(first.URL, rfClientID)
	}()
	select {
	case <-issuer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("inflight trace child issuer admission failed")
	}
	if fail {
		t.Fatal(inflightTraceFailure)
	}
	release()
	response := <-result
	if response.err != nil || response.status != http.StatusOK {
		t.Fatal("inflight trace child successful response failed")
	}
}

func checkInflightTraceProcess(t *testing.T, mode string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestRefreshGraceFailureOnlyDiagnostics$", "-test.count=1", "-test.timeout=15s")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SSO_") && !strings.HasPrefix(entry, "SNAPLINK_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, inflightTraceChildEnv+"="+mode)
	var output inflightTraceOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	err = cmd.Run()
	if ctx.Err() != nil || output.truncated || cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatal("inflight diagnostic child timeout, output overflow or missing normal Wait")
	}
	text := output.data.String()
	for _, forbidden := range []string{"panic:", "WARNING: DATA RACE", "join failed", "admission failed", "successful response failed"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("inflight diagnostic child unexpected failure: %s", forbidden)
		}
	}
	if !strings.Contains(text, "inflight trace child release confirmed") || !strings.Contains(text, "inflight trace child request joined") {
		t.Fatal("inflight diagnostic child release/join proof missing")
	}
	if mode == "success" {
		if err != nil || cmd.ProcessState.ExitCode() != 0 || strings.Contains(text, inflightTracePrefix) {
			t.Fatal("successful inflight fixture emitted diagnostics or failed")
		}
		return
	}
	var exited *exec.ExitError
	if !errors.As(err, &exited) || cmd.ProcessState.ExitCode() != 1 || strings.Count(text, "--- FAIL:") != 1 || strings.Count(text, inflightTraceFailure) != 1 {
		t.Fatal("controlled inflight diagnostic failure was not the sole normal exit1 cause")
	}
	if !strings.Contains(text, inflightTracePrefix) {
		t.Fatal("failed inflight fixture did not emit bounded phase diagnostics")
	}
	for _, phase := range []string{"server-first", "client-auth", "consume", "issuer", "signing", "grace-remember"} {
		if !strings.Contains(text, "phase="+phase+" ") {
			t.Fatalf("failed inflight fixture omitted phase %s", phase)
		}
	}
	if strings.Index(text, "inflight trace child request joined") > strings.Index(text, inflightTracePrefix) {
		t.Fatal("controlled child dumped before its explicit caller join")
	}
}

func TestRefreshGraceFailureOnlyDiagnostics(t *testing.T) {
	switch os.Getenv(inflightTraceChildEnv) {
	case "success":
		runInflightTraceChild(t, false)
		return
	case "failure":
		runInflightTraceChild(t, true)
		return
	case "":
	default:
		t.Fatal("unknown inflight diagnostic child control")
	}
	for _, mode := range []string{"success", "failure"} {
		t.Run(mode, func(t *testing.T) { checkInflightTraceProcess(t, mode) })
	}
}

func TestRefreshGraceTraceBounded(t *testing.T) {
	trace := newInflightTrace()
	for range 1024 {
		trace.mark(inflightAuth)
	}
	var lines []string
	trace.report(true, func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) })
	if len(trace.events) != 256 || trace.reserved.Load() != 1024 || len(lines) != 257 || !strings.Contains(lines[0], "dropped=768") {
		t.Fatal("inflight trace storage/output was not bounded")
	}
}

func TestRefreshGraceTraceSilenceAndActiveSnapshot(t *testing.T) {
	trace := newInflightTrace()
	index := trace.begin(inflightGraceRemember)
	trace.mark(inflightPhase(^uint32(0)))
	trace.reserved.Add(1)
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	trace.report(false, logf)
	if len(lines) != 0 {
		t.Fatal("passing trace emitted output")
	}
	trace.report(true, logf)
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "phase=grace-remember") || !strings.Contains(text, "complete=false") || !strings.Contains(text, "phase=unknown") || !strings.Contains(text, "unpublished=1") {
		t.Fatal("active/unpublished/unknown trace state was not explicit")
	}
	trace.finish(index)
	var nilTrace *inflightTrace
	nilTrace.mark(inflightAuth)
	nilTrace.report(true, logf)
	var zero inflightTrace
	if nilTrace.begin(inflightAuth) != -1 || zero.begin(inflightAuth) != -1 {
		t.Fatal("nil/zero recorder admitted an uninitialized span")
	}
}

func TestRefreshGraceTraceConcurrentSnapshot(t *testing.T) {
	trace := newInflightTrace()
	var writers sync.WaitGroup
	for range 8 {
		writers.Go(func() {
			for range 256 {
				trace.finish(trace.begin(inflightGraceLookup))
			}
		})
	}
	check := func(_ string, args ...any) {
		if len(args) == 5 && args[4].(bool) && args[3].(int64) < args[2].(int64) {
			t.Error("completed span published without its end")
		}
	}
	for range 64 {
		trace.report(true, check)
	}
	writers.Wait()
	trace.report(true, check)
	if trace.reserved.Load() != 2048 {
		t.Fatal("concurrent recording lost reservations")
	}
}

func TestRefreshGraceTraceOptionalInterfaces(t *testing.T) {
	trace := newInflightTrace()
	if traceInflightGrace(nil, trace) != nil {
		t.Fatal("nil grace became a nonnil feature")
	}
	memory := tokengrant.NewRefreshGraceCache(time.Minute)
	legacy := traceInflightGrace(completedOnlyGraceStore{store: memory}, trace)
	if _, changed := legacy.(tokengrant.RefreshGracePendingStore); changed {
		t.Fatal("legacy grace gained pending support")
	}
	observed := traceInflightGrace(memory, trace)
	pending, ok := observed.(tokengrant.RefreshGracePendingStore)
	if !ok {
		t.Fatal("pending grace lost its optional interface")
	}
	now := time.Now()
	pending.PreparePending("trace-fixture-key", map[string]any{core.KeyRefreshGracePending: true, core.KeyRefreshGraceDeadline: now.Add(time.Minute).Format(time.RFC3339Nano)}, now)
	if intent, hit := observed.Lookup("trace-fixture-key", now); !hit || intent[core.KeyRefreshGracePending] != true {
		t.Fatal("pending delegate did not reach real store")
	}
	ready := map[string]any{core.KeyAccessToken: "never-log-access", core.KeyRefreshToken: "never-log-refresh", core.KeyRefreshGraceDeadline: now.Add(time.Minute).Format(time.RFC3339Nano)}
	legacy.Remember("trace-fixture-key", ready, now)
	if got, hit := observed.Lookup("trace-fixture-key", now); !hit || got[core.KeyAccessToken] != ready[core.KeyAccessToken] {
		t.Fatal("completed delegate changed store response")
	}
	var lines []string
	trace.report(true, func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) })
	text := strings.Join(lines, "\n")
	for _, forbidden := range []string{"trace-fixture-key", "never-log-access", "never-log-refresh", ready[core.KeyRefreshGraceDeadline].(string)} {
		if strings.Contains(text, forbidden) {
			t.Fatal("inflight diagnostics leaked store input/response")
		}
	}
}

func TestRefreshGraceTraceRealAuthAndHTTP(t *testing.T) {
	memory := defaultimpl.NewMemoryClientStore()
	memory.AddSeed(&core.Client{ID: "trace-client", Secret: "trace-test-secret", Active: true})
	observed := &inflightTraceClients{MemoryClientStore: memory, trace: newInflightTrace()}
	for _, secret := range []string{"trace-test-secret", "wrong-secret"} {
		want, got := memory.ValidateSecret(t.Context(), "trace-client", secret), observed.ValidateSecret(t.Context(), "trace-client", secret)
		if (want == nil) != (got == nil) || (want != nil && want.Error() != got.Error()) {
			t.Fatal("auth observer changed real credential validation")
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, got *http.Request) {
		if got != request {
			t.Error("HTTP observer replaced request/context")
		}
		w.Header().Set("X-Trace-Test", "forwarded")
		w.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	traceInflightHandler(observed.trace, inflightFirstHTTP, next).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("X-Trace-Test") != "forwarded" {
		t.Fatal("HTTP observer changed delegated response")
	}
}
