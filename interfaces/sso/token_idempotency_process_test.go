package sso_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/shared/core"
)

const cc04ProcessEnv = "SNAPLINK_CC04_TEST_PROCESS"

// A stuck server-side Mutex.Lock cannot be cancelled by an HTTP client. Keep
// these HTTP tests in owned processes so even their failure cleanup is reaped.
var cc04Lifecycle *os.File

func cc04ProcessPlatformSupported(goos string) bool {
	// exec.Cmd.ExtraFiles cannot pass the lifecycle pipe on Windows.
	return goos != "windows"
}

func cc04InChild(t *testing.T) bool {
	t.Helper()
	if !cc04ProcessPlatformSupported(runtime.GOOS) {
		t.Skip("supervised CC process fixture requires ExtraFiles, unsupported on Windows")
	}
	if os.Getenv(cc04ProcessEnv) != t.Name() {
		return false
	}
	cc04Lifecycle = os.NewFile(3, "cc04-cleanup-events")
	t.Cleanup(func() { _ = cc04Lifecycle.Close() })
	return true
}

func cc04CleanupEvent(event byte) {
	if cc04Lifecycle != nil {
		_, _ = cc04Lifecycle.Write([]byte{event})
	}
}

func cc04Isolate(t *testing.T) bool {
	t.Helper()
	if cc04InChild(t) {
		return false
	}
	result := cc04RunChild(t)
	if result.err != nil || result.stopped != "" || !result.reaped {
		t.Fatalf("supervised HTTP test failed: stop=%s reaped=%t error=%v\n%s", result.stopped, result.reaped, result.err, result.output)
	}
	t.Logf("HTTP child pid=%d exited 0 and was reaped; child assertions:\n%s", result.pid, result.output)
	return true
}

type cc04ProcessResult struct {
	pid     int
	err     error
	stopped string
	reaped  bool
	output  string
}

func cc04RunChild(t *testing.T) cc04ProcessResult {
	t.Helper()
	if !cc04ProcessPlatformSupported(runtime.GOOS) {
		t.Skip("supervised CC process fixture requires ExtraFiles, unsupported on Windows")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd := exec.Command(binary, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v", "-test.count=1", "-test.timeout=1m")
	cmd.Env = append(os.Environ(), cc04ProcessEnv+"="+t.Name())
	cmd.ExtraFiles = []*os.File{writer}
	cmd.WaitDelay = time.Second
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	events := make(chan byte)
	stop, drained := make(chan struct{}), make(chan struct{})
	go cc04ReadEvents(reader, events, stop, drained)
	result := cc04WaitChild(cmd, events)
	close(stop)
	_ = reader.Close()
	<-drained
	result.pid, result.output = cmd.Process.Pid, output.String()
	return result
}

func cc04ReadEvents(reader io.Reader, events chan<- byte, stop <-chan struct{}, drained chan<- struct{}) {
	defer close(drained)
	defer close(events)
	var event [1]byte
	for {
		if _, err := io.ReadFull(reader, event[:]); err != nil {
			return
		}
		select {
		case events <- event[0]:
		case <-stop:
			return
		}
	}
}

func cc04WaitChild(cmd *exec.Cmd, events <-chan byte) cc04ProcessResult {
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	// The envelope is additional supervision, not a replacement for any of the
	// existing one-second request assertions or the one-second cleanup bound.
	envelope := time.NewTimer(time.Minute)
	defer envelope.Stop()
	watch := time.NewTimer(time.Second)
	watch.Stop()
	defer watch.Stop()
	var cleanup <-chan time.Time
	result := cc04ProcessResult{}
	for result.stopped == "" {
		select {
		case err := <-wait:
			result.err, result.reaped = err, cmd.ProcessState != nil
			return result
		case event, ok := <-events:
			if !ok {
				events = nil
			} else if event == 'B' {
				watch.Reset(time.Second)
				cleanup = watch.C
			} else if event == 'E' {
				watch.Stop()
				cleanup = nil
			}
		case <-cleanup:
			result.stopped = "cleanup watchdog"
		case <-envelope.C:
			result.stopped = "execution envelope"
		}
	}
	_ = cmd.Process.Kill()
	result.err = <-wait // Always reap the actual child before returning.
	result.reaped = cmd.ProcessState != nil
	return result
}

func TestClientCredentialsIdempotencyCleanupReapsStuckHandler(t *testing.T) {
	if cc04InChild(t) {
		var stuck sync.Mutex
		stuck.Lock() // Deliberately never released: only killing the child can reap it.
		entered := make(chan struct{})
		issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
		issuer.before = func(_ *core.Subject, _ []string) error {
			close(entered)
			stuck.Lock()
			return nil
		}
		g, _ := newCC04Requests(t, issuer, cc04Memory(t), nil)
		response := g.start(cc04Request("read"), "cleanup-negative-fixture")
		select {
		case <-entered:
			t.Log("negative fixture reached uncancellable server-side mutex")
		case <-time.After(time.Second):
			t.Fatal("negative fixture did not reach controlled mutex")
		}
		cc04Await(t, response) // Original one-second assertion must fail, then cleanup must be supervised.
		t.Fatal("negative fixture unexpectedly completed")
	}
	result := cc04RunChild(t)
	var exit *exec.ExitError
	if result.stopped != "cleanup watchdog" || !result.reaped || !errors.As(result.err, &exit) {
		t.Fatalf("stuck handler was not killed and reaped by cleanup watchdog: stop=%s reaped=%t error=%v\n%s", result.stopped, result.reaped, result.err, result.output)
	}
	for _, required := range []string{"negative fixture reached uncancellable server-side mutex", "request did not complete within existing one-second watchdog"} {
		if !strings.Contains(result.output, required) {
			t.Fatalf("negative fixture did not prove original assertion and stuck cleanup: missing %q\n%s", required, result.output)
		}
	}
	t.Logf("negative child pid=%d stop=%s reaped=%t actual exit=%v; expected assertion output=%q", result.pid, result.stopped, result.reaped, result.err, result.output)
}
