package ssotest

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

type refOutageWorker struct {
	down, up net.Conn
	cancel   context.CancelFunc
	done     chan struct{}
}

type refOutageStop struct {
	worker *refOutageWorker
	up     net.Conn
}

// No PostgreSQL parsing or payload logging. op serializes transitions, while
// mu protects attachment: no dial/copy/wait/socket Close holds that mutex.
// Registration precedes goroutine launch; done means BOTH copy loops ended.
type refOutageGate struct {
	op, mu                      sync.Mutex
	listener                    net.Listener
	target                      string
	dial                        func(context.Context, string, string) (net.Conn, error)
	open, closed, drained       bool
	generation                  uint64
	workers                     map[*refOutageWorker]struct{}
	acceptDone                  chan struct{}
	acceptErr                   error
	joined                      bool
	started, finished, attached int
}

func newRefOutageGate(t *testing.T, target string, dial func(context.Context, string, string) (net.Conn, error)) *refOutageGate {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	refProcessCheck(t, err, "open loopback PostgreSQL TCP gate")
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	g := &refOutageGate{listener: listener, target: target, dial: dial, open: true,
		workers: map[*refOutageWorker]struct{}{}, acceptDone: make(chan struct{})}
	go g.accept()
	t.Cleanup(func() {
		refProcessCheck(t, g.Close(), "close and join all TCP gate workers")
		started, finished, attached, active := g.counts()
		t.Logf("TCP gate joined: started=%d finished=%d attached=%d active=%d", started, finished, attached, active)
	})
	return g
}

func (g *refOutageGate) accept() {
	defer close(g.acceptDone)
	for {
		down, err := g.listener.Accept()
		if err != nil {
			g.mu.Lock()
			if !g.closed || !errors.Is(err, net.ErrClosed) {
				g.acceptErr = errors.New("unexpected gate accept failure")
			}
			g.mu.Unlock()
			return
		}
		g.mu.Lock()
		if !g.open || g.closed {
			g.mu.Unlock()
			_ = down.Close()
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		w := &refOutageWorker{down: down, cancel: cancel, done: make(chan struct{})}
		generation := g.generation
		g.workers[w] = struct{}{}
		g.started++
		g.mu.Unlock()
		go g.forward(ctx, w, generation)
	}
}

func (g *refOutageGate) forward(ctx context.Context, w *refOutageWorker, generation uint64) {
	defer func() {
		w.cancel()
		_ = w.down.Close()
		g.mu.Lock()
		delete(g.workers, w)
		g.finished++
		close(w.done)
		g.mu.Unlock()
	}()
	up, err := g.dial(ctx, "tcp", g.target)
	if err != nil {
		if up != nil {
			_ = up.Close()
		}
		return
	}
	defer up.Close()
	g.mu.Lock()
	if !g.open || g.closed || generation != g.generation || ctx.Err() != nil {
		g.mu.Unlock()
		return
	}
	w.up = up
	g.attached++
	g.mu.Unlock()
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(w.down, up); close(copied) }()
	_, _ = io.Copy(up, w.down)
	_ = up.Close()
	_ = w.down.Close()
	<-copied
}

func (g *refOutageGate) stopsLocked() []refOutageStop {
	stops := make([]refOutageStop, 0, len(g.workers))
	for w := range g.workers {
		stops = append(stops, refOutageStop{w, w.up})
	}
	return stops
}

func refOutageDrain(ctx context.Context, stops []refOutageStop) error {
	for _, stop := range stops {
		stop.worker.cancel()
		_ = stop.worker.down.Close()
		if stop.up != nil {
			_ = stop.up.Close()
		}
	}
	for _, stop := range stops {
		select {
		case <-stop.worker.done:
		case <-ctx.Done():
			return errors.New("TCP gate workers did not join within bound")
		}
	}
	return nil
}

func (g *refOutageGate) Cut(ctx context.Context) error {
	g.op.Lock()
	defer g.op.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	g.mu.Lock()
	if !g.open || g.closed {
		g.mu.Unlock()
		return errors.New("TCP cut requires an open gate")
	}
	g.open = false
	g.generation++
	stops := g.stopsLocked()
	g.mu.Unlock()
	if err := refOutageDrain(ctx, stops); err != nil {
		return err
	}
	g.mu.Lock()
	g.drained = true
	g.mu.Unlock()
	return nil
}

func (g *refOutageGate) Restore() error {
	g.op.Lock()
	defer g.op.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.open || !g.drained {
		return errors.New("TCP restore requires a completed cut")
	}
	g.open, g.drained = true, false
	return nil
}

func (g *refOutageGate) Close() error {
	g.op.Lock()
	defer g.op.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g.mu.Lock()
	g.closed, g.open = true, false
	g.generation++
	stops := g.stopsLocked()
	g.mu.Unlock()
	_ = g.listener.Close()
	if err := refOutageDrain(ctx, stops); err != nil {
		return err
	}
	select {
	case <-g.acceptDone:
	case <-ctx.Done():
		return errors.New("TCP gate accept loop did not join within bound")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.joined = g.acceptErr == nil && len(g.workers) == 0
	return g.acceptErr
}

func (g *refOutageGate) teardownSafe() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.joined
}

func (g *refOutageGate) counts() (int, int, int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.started, g.finished, g.attached, len(g.workers)
}

func refOutageWait(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(operation + " did not finish")
	}
}

func refOutageEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	refProcessCheck(t, err, "open echo control")
	done := make(chan struct{})
	var copies sync.WaitGroup
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				copies.Wait()
				return
			}
			copies.Add(1)
			go func() { defer copies.Done(); defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); refOutageWait(t, done, "echo workers") })
	return listener.Addr().String()
}

func refOutageConnect(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	refProcessCheck(t, err, "connect loopback fault control")
	t.Cleanup(func() { _ = conn.Close() })
	refProcessCheck(t, conn.SetDeadline(time.Now().Add(5*time.Second)), "bound fault control IO")
	return conn
}

func refOutageRoundtrip(t *testing.T, conn net.Conn) {
	t.Helper()
	_, err := conn.Write([]byte("control"))
	refProcessCheck(t, err, "write echo control")
	value := make([]byte, 7)
	_, err = io.ReadFull(conn, value)
	refProcessCheck(t, err, "read echo control")
	if string(value) != "control" {
		t.Fatal("TCP gate changed payload")
	}
}

func TestStockPostgresOutageProxyCutAndRestore(t *testing.T) {
	g := newRefOutageGate(t, refOutageEcho(t), nil)
	if g.Restore() == nil || g.teardownSafe() {
		t.Fatal("open gate incorrectly accepted restore or schema teardown")
	}
	conn := refOutageConnect(t, g.listener.Addr().String())
	refOutageRoundtrip(t, conn)
	refProcessCheck(t, g.Cut(t.Context()), "cut and drain active forwarding")
	started, finished, attached, active := g.counts()
	if started != finished || active != 0 || attached != 1 {
		t.Fatal("cut returned without actual forwarding completion")
	}
	var value [1]byte
	if _, err := conn.Read(value[:]); err == nil {
		t.Fatal("cut left original connection readable")
	}
	blocked := refOutageConnect(t, g.listener.Addr().String())
	_, _ = blocked.Write(value[:])
	if _, err := blocked.Read(value[:]); err == nil {
		t.Fatal("cut admitted a new upstream connection")
	}
	_, _, nowAttached, _ := g.counts()
	if nowAttached != attached {
		t.Fatal("cut forwarded to upstream")
	}
	refProcessCheck(t, g.Restore(), "restore same listener")
	refOutageRoundtrip(t, refOutageConnect(t, g.listener.Addr().String()))
}

func TestStockPostgresOutageProxyCancelsDial(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	up, peer := net.Pipe()
	t.Cleanup(func() { _ = up.Close(); _ = peer.Close() })
	g := newRefOutageGate(t, "unused", func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release // A late dial result must not attach, even if it returns success.
		return up, nil
	})
	t.Cleanup(unblock) // Registered after gate cleanup: release before Close/join.
	_ = refOutageConnect(t, g.listener.Addr().String())
	refOutageWait(t, entered, "controlled dial entry")
	if os.Getenv(refOutageProbeEnv) == "dial-early" {
		t.Fatal("controlled dial assertion failure before release")
	}
	cut, cutDone := make(chan error, 1), make(chan struct{})
	go func() { cut <- g.Cut(t.Context()); close(cutDone) }()
	t.Cleanup(func() { unblock(); refOutageWait(t, cutDone, "cut goroutine cleanup") })
	refOutageWait(t, canceled, "dial cancellation")
	select {
	case <-cut:
		t.Fatal("cut returned before canceled dial joined")
	default:
	}
	unblock()
	refOutageWait(t, cutDone, "cut goroutine")
	refProcessCheck(t, <-cut, "join late canceled dial")
	refProcessCheck(t, g.Restore(), "restore after joined dial")
	started, finished, attached, active := g.counts()
	if started != 1 || finished != 1 || attached != 0 || active != 0 {
		t.Fatal("pre-cut dial crossed generation or was not joined")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var value [1]byte
	if _, err := peer.Read(value[:]); !errors.Is(err, io.EOF) {
		t.Fatal("late upstream socket was not closed")
	}
}

const refOutageProbeEnv = "SNAPLINK_OUTAGE_PROXY_FAILURE_PROBE"

// A failed assertion must still release controlled blockers and join the gate.
// Re-execution keeps the expected child failure from failing the parent test.
func TestStockPostgresOutageProxyFailureCleanup(t *testing.T) {
	bin, err := os.Executable()
	refProcessCheck(t, err, "find proxy lifecycle probe executable")
	for _, probe := range []struct{ mode, test, failure, attachment string }{
		{"dial-early", "ProxyCancelsDial", "controlled dial assertion failure before release", "attached=0"},
		{"copy-early", "ProxyCloseJoins", "controlled copy assertion failure before release", "attached=1"},
		{"no-forward", "ProxyCloseJoins", "prove active upstream copy failed", "attached=0"},
	} {
		t.Run(probe.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "-test.run=^TestStockPostgresOutage"+probe.test+"$", "-test.timeout=10s", "-test.v")
			cmd.Env = append(os.Environ(), refOutageProbeEnv+"="+probe.mode)
			output, err := cmd.CombinedOutput()
			text := string(output)
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 || cmd.ProcessState == nil ||
				!strings.Contains(text, probe.failure) || !strings.Contains(text, "TCP gate joined: started=1 finished=1 "+probe.attachment+" active=0") ||
				strings.Contains(text, "panic:") || strings.Contains(text, "WARNING: DATA RACE") {
				t.Fatal("controlled assertion failure did not exit1 with Wait and complete gate join (private probe output withheld)")
			}
			t.Logf("controlled proxy failure mode=%s: child Wait exit1, blocker released, gate joined; expected child failure", probe.mode)
		})
	}
}

type refOutageBlockedRead struct {
	net.Conn
	release, closed chan struct{}
	once            sync.Once
}

func (c *refOutageBlockedRead) Read([]byte) (int, error) { <-c.release; return 0, io.EOF }
func (c *refOutageBlockedRead) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestStockPostgresOutageProxyCloseJoins(t *testing.T) {
	up, peer := net.Pipe()
	t.Cleanup(func() { _ = up.Close(); _ = peer.Close() })
	refProcessCheck(t, peer.SetDeadline(time.Now().Add(5*time.Second)), "bound upstream copy probe")
	blocked := &refOutageBlockedRead{Conn: up, release: make(chan struct{}), closed: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(blocked.release) })
	entered := make(chan struct{})
	g := newRefOutageGate(t, "unused", func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		if os.Getenv(refOutageProbeEnv) == "no-forward" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return blocked, nil
	})
	t.Cleanup(unblock) // Fatal assertions must not leave the controlled Read held.
	conn := refOutageConnect(t, g.listener.Addr().String())
	refOutageWait(t, entered, "copy dial entry")
	// Write completes only after attachment and the downstream copy starts.
	writeDone := make(chan struct{})
	go func() { _, _ = conn.Write([]byte("x")); close(writeDone) }()
	t.Cleanup(func() { _ = conn.Close(); unblock(); refOutageWait(t, writeDone, "control writer cleanup") })
	var value [1]byte
	_, err := peer.Read(value[:])
	refProcessCheck(t, err, "prove active upstream copy")
	refOutageWait(t, writeDone, "control writer")
	if os.Getenv(refOutageProbeEnv) == "copy-early" {
		t.Fatal("controlled copy assertion failure before release")
	}
	closed, closeDone := make(chan error, 1), make(chan struct{})
	go func() { closed <- g.Close(); close(closeDone) }()
	t.Cleanup(func() { unblock(); refOutageWait(t, closeDone, "Close goroutine cleanup") })
	refOutageWait(t, blocked.closed, "socket close request")
	if g.teardownSafe() {
		t.Fatal("socket Close incorrectly certified a still-running copy as joined")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before both copies joined")
	default:
	}
	unblock()
	refOutageWait(t, closeDone, "Close goroutine")
	refProcessCheck(t, <-closed, "join active copy")
	refProcessCheck(t, g.Close(), "idempotent gate Close")
	if !g.teardownSafe() || g.Restore() == nil || g.Cut(t.Context()) == nil {
		t.Fatal("terminal gate state or teardown proof incorrect")
	}
}
