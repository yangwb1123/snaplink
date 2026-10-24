package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

// This source-spine assertion checks cleanup ownership, not startup reachability
// or configuration/retention policy. No app, store or listener is constructed.
func TestStartupExitCleanup_RunOwnsDeferredTeardown(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run *ast.FuncDecl
	for _, node := range file.Decls {
		if fn, ok := node.(*ast.FuncDecl); ok && fn.Name.Name == "run" {
			run = fn
		}
	}
	if run == nil || run.Type.Results == nil || len(run.Type.Results.List) != 1 || len(run.Type.Results.List[0].Names) != 1 || run.Type.Results.List[0].Names[0].Name != "retErr" {
		t.Fatal("run must preserve its returned error for deferred cleanup reporting")
	}
	var owner *ast.DeferStmt
	var stores *ast.DeferStmt
	for _, statement := range run.Body.List {
		deferred, ok := statement.(*ast.DeferStmt)
		if !ok {
			continue
		}
		if id, ok := deferred.Call.Fun.(*ast.Ident); ok && id.Name == "closeAppStores" {
			stores = deferred
		}
		literal, ok := deferred.Call.Fun.(*ast.FuncLit)
		if !ok || len(literal.Body.List) != 1 {
			continue
		}
		expr, ok := literal.Body.List[0].(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if ok && startupCleanupCallName(call) == "shutdownRuntime" {
			if owner != nil || len(call.Args) != 4 {
				t.Fatal("exactly one late-bound teardown owner is required")
			}
			owner = deferred
			checkStartupCleanupArgs(t, call)
		}
	}
	if owner == nil || stores == nil || stores.Pos() >= owner.Pos() {
		t.Fatal("deferred runtime teardown must run before deferred backing-store close")
	}
	ast.Inspect(run.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch startupCleanupCallName(call) {
		case "wireRateLimitReload", "runBootstrap", "buildHTTPServer", "startHTTPServer", "startPprofServer", "startGRPCServer", "waitForShutdown":
			if call.Pos() <= owner.End() {
				t.Fatal("cleanup owner must be installed before post-build effects")
			}
		case "shutdownServers", "shutdownSubsystems":
			t.Fatal("run must not duplicate teardown outside its single deferred owner")
		}
		return true
	})
}

func startupCleanupCallName(call *ast.CallExpr) string {
	if id, ok := call.Fun.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func checkStartupCleanupArgs(t *testing.T, call *ast.CallExpr) {
	t.Helper()
	for index, name := range []string{"a", "servers", "logger"} {
		id, ok := call.Args[index].(*ast.Ident)
		if !ok || id.Name != name {
			t.Fatal("deferred owner must use the actual late-bound runtime handles")
		}
	}
	completion, ok := call.Args[3].(*ast.BinaryExpr)
	if !ok || completion.Op != token.LAND {
		t.Fatal("clean-stop logging also requires normal completion, not panic unwinding")
	}
	flag, ok := completion.X.(*ast.Ident)
	if !ok || flag.Name != "cleanStop" {
		t.Fatal("clean-stop logging must require cleanStop")
	}
	condition, ok := completion.Y.(*ast.BinaryExpr)
	if !ok || condition.Op != token.EQL {
		t.Fatal("clean-stop logging must depend on the returned error")
	}
	left, lok := condition.X.(*ast.Ident)
	right, rok := condition.Y.(*ast.Ident)
	if !lok || !rok || left.Name != "retErr" || right.Name != "nil" {
		t.Fatal("clean-stop logging must be retErr == nil")
	}
}

func TestStartupExitCleanup_CleanFlagOnlyOnNormalReturn(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range file.Decls {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			continue
		}
		var assignments []string
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if !ok || name.Name != "cleanStop" {
				return true
			}
			value, ok := assignment.Rhs[0].(*ast.Ident)
			if !ok {
				t.Fatal("clean-stop completion flag must be literal")
			}
			assignments = append(assignments, value.Name)
			return true
		})
		if !reflect.DeepEqual(assignments, []string{"false", "true"}) {
			t.Fatalf("completion assignments = %v", assignments)
		}
		last := fn.Body.List
		assignment, ok := last[len(last)-2].(*ast.AssignStmt)
		if !ok || startupCleanupAssignmentName(assignment) != "cleanStop" {
			t.Fatal("normal completion must be set only immediately before final success return")
		}
		return
	}
	t.Fatal("run not found")
}

// main's direct os.Exit on a run failure would skip the deferred outer
// cleanup (tracing flush, then config-source close), so the error branch must
// invoke the shared outer-cleanup helper before exiting. This pins the
// wiring; the helper's ordering and context behavior are covered separately.
func TestStartupExitCleanup_RunErrorFlushesOuterCleanup(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	branch := startupCleanupRunErrorBranch(t, file)
	if len(branch.Body.List) != 3 {
		t.Fatalf("run error branch statements = %d, want log + outer cleanup + exit", len(branch.Body.List))
	}
	cleanup, ok := branch.Body.List[1].(*ast.ExprStmt)
	if !ok {
		t.Fatal("run error branch must flush outer cleanup before os.Exit")
	}
	call, ok := cleanup.X.(*ast.CallExpr)
	if !ok || startupCleanupCallName(call) != "runErrorCleanup" {
		t.Fatal("run error branch must call the shared outer-cleanup helper before os.Exit")
	}
	for index, name := range []string{"tracingShutdown", "cleanupSources"} {
		arg, ok := call.Args[index].(*ast.Ident)
		if !ok || arg.Name != name {
			t.Fatalf("run error cleanup arg %d = %v, want %s", index, call.Args[index], name)
		}
	}
	exit, ok := branch.Body.List[2].(*ast.ExprStmt)
	if !ok {
		t.Fatal("run error branch must keep the process exit after cleanup")
	}
	exitCall, ok := exit.X.(*ast.CallExpr)
	if !ok {
		t.Fatal("run error branch must keep the process exit after cleanup")
	}
	selector, ok := exitCall.Fun.(*ast.SelectorExpr)
	if !ok {
		t.Fatal("run error branch must keep os.Exit after cleanup")
	}
	base, ok := selector.X.(*ast.Ident)
	if !ok || base.Name != "os" || selector.Sel.Name != "Exit" || len(exitCall.Args) != 1 {
		t.Fatal("run error branch must keep os.Exit(1) after cleanup")
	}
	status, ok := exitCall.Args[0].(*ast.BasicLit)
	if !ok || status.Kind != token.INT || status.Value != "1" {
		t.Fatal("run error branch must keep exit status 1")
	}
}

func startupCleanupRunErrorBranch(t *testing.T, file *ast.File) *ast.IfStmt {
	t.Helper()
	for _, node := range file.Decls {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" {
			continue
		}
		var branch *ast.IfStmt
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			stmt, ok := node.(*ast.IfStmt)
			if !ok || stmt.Init == nil {
				return true
			}
			assign, ok := stmt.Init.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			ident, ok := assign.Lhs[0].(*ast.Ident)
			if !ok || ident.Name != "err" {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if ok && startupCleanupCallName(call) == "run" {
				branch = stmt
			}
			return true
		})
		if branch != nil {
			return branch
		}
	}
	t.Fatal("main must branch on the error returned by run")
	return nil
}

// runErrorCleanup must flush tracing under the existing bounded process-exit
// context and then close config sources, matching main's defer order even when
// the flush itself reports an error.
func TestStartupExitCleanup_RunErrorCleanupOrderAndContext(t *testing.T) {
	var order []string
	tracing := func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
			t.Error("tracing flush must use the existing bounded process-exit context")
		}
		order = append(order, "tracing")
		return errors.New("flush unavailable")
	}
	cleanup := func() { order = append(order, "sources") }
	runErrorCleanup(tracing, cleanup)
	if !reflect.DeepEqual(order, []string{"tracing", "sources"}) {
		t.Fatalf("run error outer cleanup order = %v, want tracing before config sources", order)
	}
}

func startupCleanupAssignmentName(assignment *ast.AssignStmt) string {
	if len(assignment.Lhs) == 1 {
		if id, ok := assignment.Lhs[0].(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func TestStartupExitCleanup_PartialServerHandles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	healthStops := 0
	// This gRPC server has no listener, services or external transport.
	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()
	shutdownServers(ctx, newSlogLogger("error"), nil, nil, grpcServer, func() { healthStops++ })
	if healthStops != 1 {
		t.Fatalf("health stop calls = %d, want 1", healthStops)
	}
}

func TestStartupExitCleanup_FailedGRPCBindStopsHealth(t *testing.T) {
	// A failed gRPC bind leaves no retained *grpc.Server handle in the runtime
	// server set, but newGRPCServer has already registered the readiness
	// poller and stored its stop on the app before net.Listen ran. The deferred
	// owner must still invoke that stop, or the poller outlives teardown with
	// no returned handle left to close it.
	a := &app{}
	healthStops := 0
	a.grpcHealthStop = func() { healthStops++ }
	shutdownRuntime(a, runtimeServers{}, &startupCleanupLogger{}, false)
	if healthStops != 1 {
		t.Fatalf("failed gRPC bind health stop calls = %d, want 1", healthStops)
	}
}

func TestStartupExitCleanup_RuntimeDrainsBeforeAuditClose(t *testing.T) {
	for _, listeners := range []bool{false, true} {
		for _, clean := range []bool{false, true} {
			t.Run(fmtStartupCleanupCase(listeners, clean), func(t *testing.T) {
				logger := &startupCleanupLogger{}
				servers := runtimeServers{}
				var tracked []*startupCleanupListener
				if listeners {
					servers.http, tracked = startupCleanupHTTP(t, tracked)
					servers.pprof, tracked = startupCleanupHTTP(t, tracked)
					servers.grpc = grpc.NewServer()
					t.Cleanup(servers.grpc.Stop)
				}
				var order []string
				done := make(chan struct{})
				a := &app{clientSecretScanDone: done}
				a.clientSecretScanCancel = func() {
					for _, listener := range tracked {
						if !listener.closed.Load() {
							t.Error("worker cancelled before owned listener closed")
						}
					}
					order = append(order, "cancel")
					close(done)
				}
				a.externalAuditClose = func(ctx context.Context) error {
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > shutdownTimeout {
						t.Error("audit close must use the existing bounded shutdown context")
					}
					order = append(order, "audit")
					return nil
				}
				shutdownRuntime(a, servers, logger, clean)
				if !reflect.DeepEqual(order, []string{"cancel", "audit"}) {
					t.Fatalf("teardown order = %v", order)
				}
				if (len(logger.info) == 1) != clean || (clean && logger.info[0] != "server stopped cleanly") {
					t.Fatalf("clean=%v messages=%v", clean, logger.info)
				}
			})
		}
	}
}

func fmtStartupCleanupCase(listeners, clean bool) string {
	name := "partial"
	if listeners {
		name = "listeners"
	}
	if clean {
		return name + "_clean"
	}
	return name + "_error"
}

type startupCleanupLogger struct{ info []string }

func (l *startupCleanupLogger) Info(msg string, _ ...any) { l.info = append(l.info, msg) }
func (*startupCleanupLogger) Error(string, ...any)        {}
func (*startupCleanupLogger) Debug(string, ...any)        {}

type startupCleanupListener struct {
	net.Listener
	closed  atomic.Bool
	started chan struct{}
	once    sync.Once
}

func (l *startupCleanupListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.started) })
	return l.Listener.Accept()
}

func (l *startupCleanupListener) Close() error {
	l.closed.Store(true)
	return l.Listener.Close()
}

func startupCleanupHTTP(t *testing.T, tracked []*startupCleanupListener) (*http.Server, []*startupCleanupListener) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owned := &startupCleanupListener{Listener: listener, started: make(chan struct{})}
	server := &http.Server{Handler: http.NotFoundHandler()}
	done := make(chan error, 1)
	go func() { done <- server.Serve(owned) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-done:
			if err != http.ErrServerClosed {
				t.Errorf("owned HTTP exit: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("owned HTTP listener did not stop")
		}
	})
	select {
	case <-owned.started:
	case <-time.After(2 * time.Second):
		t.Fatal("owned HTTP listener did not become ready")
	}
	return server, append(tracked, owned)
}

// buildApp allocates the shared Redis client and Postgres pool before its
// store/foundation phases run, so the failure-cleanup defer must already be
// installed when those pools are created; otherwise a post-Redis failure (a
// Postgres dial error or an HA-coherence rejection) returns with no owner left
// to release the pool. This is a source-spine ordering pin only.
func TestStartupExitCleanup_BuildFailureOwnerPrecedesSharedPools(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "build_stores.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range file.Decls {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "buildApp" {
			continue
		}
		owner := token.NoPos
		var pools []token.Pos
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch startupCleanupMethodName(call) {
			case "closeBuildFailure":
				owner = call.Pos()
			case "wireRedis", "wirePostgres":
				pools = append(pools, call.Pos())
			}
			return true
		})
		if owner == token.NoPos {
			t.Fatal("buildApp must install its failure-cleanup owner")
		}
		if len(pools) != 2 {
			t.Fatalf("buildApp shared-pool wire calls = %d, want wireRedis + wirePostgres", len(pools))
		}
		for _, at := range pools {
			if at < owner {
				t.Fatal("failure cleanup must be installed before the shared pools are allocated")
			}
		}
		return
	}
	t.Fatal("buildApp not found")
}

func startupCleanupMethodName(call *ast.CallExpr) string {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		return selector.Sel.Name
	}
	return ""
}

// The shared Redis client and Postgres pool outlive individual stores, so the
// build-failure owner must release them; otherwise a failed build strands an
// open pool for the rest of the process lifetime. No data or schema is touched:
// the pool is replaced by an inert in-memory driver and a close-counting stub.
func TestStartupExitCleanup_BuildFailureClosesSharedPools(t *testing.T) {
	redis := &startupCleanupRedis{}
	db := sql.OpenDB(startupCleanupConnector{})
	checked, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("precondition: owned fake pool must open: %v", err)
	}
	_ = checked.Close()
	b := &appBuilder{redis: redis, pgDB: db, logger: &startupCleanupLogger{}}
	b.closeBuildFailure()
	if got := redis.closes.Load(); got != 1 {
		t.Errorf("shared redis close calls = %d, want 1", got)
	}
	if _, err := db.Conn(context.Background()); err == nil {
		t.Error("shared postgres pool is still open after build-failure cleanup")
	}
}

type startupCleanupRedis struct {
	goredis.UniversalClient
	closes atomic.Int32
}

func (r *startupCleanupRedis) Close() error {
	r.closes.Add(1)
	return nil
}

// startupCleanupConnector yields an inert in-memory driver so the pool's
// open/closed state is observable without a network or a real database.
type startupCleanupConnector struct{}

func (startupCleanupConnector) Connect(context.Context) (driver.Conn, error) {
	return startupCleanupConn{}, nil
}
func (startupCleanupConnector) Driver() driver.Driver { return startupCleanupDriver{} }

type startupCleanupDriver struct{}

func (startupCleanupDriver) Open(string) (driver.Conn, error) { return startupCleanupConn{}, nil }

type startupCleanupConn struct{}

func (startupCleanupConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("inert test connection")
}
func (startupCleanupConn) Close() error { return nil }
func (startupCleanupConn) Begin() (driver.Tx, error) {
	return nil, errors.New("inert test connection")
}
