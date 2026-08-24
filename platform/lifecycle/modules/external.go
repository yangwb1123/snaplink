package modules

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// ExternalProtocolVersion is the typed RPC protocol version spoken by the
// external-module supervisor and its independently installed workers.
const ExternalProtocolVersion uint32 = 1

const (
	ExternalCapabilityAuditBatch  ExternalCapability = "deliver_audit_batch"
	defaultExternalStartupTimeout                    = 5 * time.Second
	defaultExternalRequestTimeout                    = 10 * time.Second
	defaultExternalFrameBytes                        = 1 << 20
	defaultExternalBatchEvents                       = 256
	maxExternalFrameBytes                            = 16 << 20
	maxExternalBatchEvents                           = 10_000
	externalMethodHandshake                          = "handshake"
	externalMethodReady                              = "ready"
	externalMethodHeartbeat                          = "heartbeat"
	externalMethodQuiesce                            = "quiesce"
	externalMethodShutdown                           = "shutdown"
	externalMethodAuditBatch                         = "deliver_audit_batch"
)

// ExternalCapability is a fixed, typed external-worker data-plane method.
// There is intentionally no generic Execute/JSON escape hatch.
type ExternalCapability string

// ExternalModuleSpec selects one external worker. Local workers use an
// absolute Unix socket and are executed directly (never through a shell);
// ExpectedSHA256 is mandatory and SignaturePath/SignaturePublicKey can add a
// detached Ed25519 signature over that digest. Remote workers use
// RemoteAddress with a TLSConfig that presents a client certificate; no local
// process or digest fields are accepted in that mode.
type ExternalModuleSpec struct {
	ModuleID             string
	Executable           string
	Args                 []string
	SocketPath           string
	AuthToken            []byte
	ExpectedSHA256       string
	SignaturePath        string
	SignaturePublicKey   []byte
	ProvenancePath       string
	ProvenancePublicKey  []byte
	RequiredReleaseID    string
	RequiredBuildProfile string
	RemoteAddress        string
	TLSConfig            *tls.Config
	PeerSPIFFEID         string
	RequiredCapabilities []ExternalCapability
	StartupTimeout       time.Duration
	RequestTimeout       time.Duration
	MaxFrameBytes        int
	MaxBatchEvents       int
}

// ExternalServerOptions describes the host-authenticated side of one worker
// connection. The worker owns the listener and calls ServeExternalConnection
// after accepting either a Unix-domain or already-handshaken TLS connection.
type ExternalServerOptions struct {
	ModuleID        string
	ProtocolVersion uint32
	AuthToken       []byte
	Capabilities    []ExternalCapability
	Ready           func(context.Context) error
	Heartbeat       func(context.Context) error
	Quiesce         func(context.Context) error
	Shutdown        func(context.Context) error
	MaxFrameBytes   int
	MaxBatchEvents  int
}

// ExternalAuditHandler is the only data-plane interface currently exposed to
// external workers. The host remains responsible for audit redaction and for
// deciding which events may be sent.
type ExternalAuditHandler interface {
	DeliverAuditBatch(context.Context, []audit.Event) error
}

// ExternalSupervisor owns one authenticated worker process and its typed RPC
// connection. It is deliberately separate from Manager: a host can place this
// client behind a generation Instance, while third-party code remains out of
// process and cannot access host signing keys or bearer credentials.
type ExternalSupervisor struct {
	spec ExternalModuleSpec

	mu        sync.RWMutex
	cmd       *exec.Cmd
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	quiescing bool
	stopped   bool
	rpcMu     sync.Mutex
	requestID atomic.Uint64
}

// NewExternalSupervisor validates and freezes the external-worker policy.
func NewExternalSupervisor(spec ExternalModuleSpec) (*ExternalSupervisor, error) {
	if err := validateExternalSpec(spec); err != nil {
		return nil, err
	}
	if spec.StartupTimeout <= 0 {
		spec.StartupTimeout = defaultExternalStartupTimeout
	}
	if spec.RequestTimeout <= 0 {
		spec.RequestTimeout = defaultExternalRequestTimeout
	}
	if spec.MaxFrameBytes <= 0 {
		spec.MaxFrameBytes = defaultExternalFrameBytes
	}
	if spec.MaxBatchEvents <= 0 {
		spec.MaxBatchEvents = defaultExternalBatchEvents
	}
	spec.Args = append([]string(nil), spec.Args...)
	spec.AuthToken = append([]byte(nil), spec.AuthToken...)
	spec.SignaturePublicKey = append([]byte(nil), spec.SignaturePublicKey...)
	spec.ProvenancePublicKey = append([]byte(nil), spec.ProvenancePublicKey...)
	spec.TLSConfig = cloneExternalTLSConfig(spec.TLSConfig, spec.PeerSPIFFEID)
	spec.RequiredCapabilities = append([]ExternalCapability(nil), spec.RequiredCapabilities...)
	return &ExternalSupervisor{spec: spec}, nil
}

func validateExternalSpec(spec ExternalModuleSpec) error {
	if strings.TrimSpace(spec.ModuleID) == "" || strings.ContainsAny(spec.ModuleID, "/\\") {
		return errors.New("external module: invalid module id")
	}
	if len(spec.AuthToken) == 0 {
		return errors.New("external module: auth token is required")
	}
	if err := validateExternalLimits(spec); err != nil {
		return err
	}
	if strings.TrimSpace(spec.RemoteAddress) != "" {
		return validateExternalRemoteSpec(spec)
	}
	return validateExternalLocalSpec(spec)
}

func validateExternalLimits(spec ExternalModuleSpec) error {
	if spec.StartupTimeout > 10*time.Minute || spec.RequestTimeout > 10*time.Minute {
		return errors.New("external module: timeout exceeds 10m safety bound")
	}
	if spec.MaxFrameBytes > maxExternalFrameBytes || spec.MaxBatchEvents > maxExternalBatchEvents {
		return errors.New("external module: size limit exceeds safety bound")
	}
	return nil
}

func validateExternalLocalSpec(spec ExternalModuleSpec) error {
	if strings.TrimSpace(spec.Executable) == "" || !filepath.IsAbs(spec.Executable) || !filepath.IsAbs(spec.SocketPath) {
		return errors.New("external module: absolute executable and socket path are required")
	}
	digest, err := hex.DecodeString(strings.TrimSpace(spec.ExpectedSHA256))
	if err != nil || len(digest) != sha256.Size {
		return errors.New("external module: expected_sha256 must be a 64-character hex digest")
	}
	return validateExternalSignatureSpec(spec)
}

// Start verifies, launches, connects and handshakes the worker before making
// it available to callers. A failed candidate is killed and its socket is not
// reused implicitly.
func (s *ExternalSupervisor) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("external module: nil supervisor")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.stopped || s.cmd != nil || s.conn != nil {
		s.mu.Unlock()
		return errors.New("external module: already started or stopped")
	}
	s.mu.Unlock()
	if err := s.startLocalProcess(); err != nil {
		return err
	}
	conn, err := s.dial(ctx)
	if err == nil {
		s.installConnection(conn)
		err = s.handshake(ctx)
	}
	if err == nil {
		err = s.Ready(ctx)
	}
	if err != nil {
		s.abortStart()
		return err
	}
	return nil
}

func (s *ExternalSupervisor) startLocalProcess() error {
	if s.spec.RemoteAddress != "" {
		return nil
	}
	if err := verifyExternalExecutable(s.spec.Executable, s.spec.ExpectedSHA256, s.spec.SignaturePath, s.spec.SignaturePublicKey, s.spec.ProvenancePath, s.spec.ProvenancePublicKey, s.spec.ModuleID, s.spec.RequiredReleaseID, s.spec.RequiredBuildProfile); err != nil {
		return err
	}
	cmd := exec.Command(s.spec.Executable, s.spec.Args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("external module: start %s: %w", s.spec.ModuleID, err)
	}
	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()
	return nil
}

func (s *ExternalSupervisor) dial(ctx context.Context) (net.Conn, error) {
	deadline := time.Now().Add(s.spec.StartupTimeout)
	network, address := "unix", s.spec.SocketPath
	if s.spec.RemoteAddress != "" {
		network, address = "tcp", s.spec.RemoteAddress
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("external module: startup timeout")
		}
		if remaining > 200*time.Millisecond {
			remaining = 200 * time.Millisecond
		}
		conn, err := dialExternalAddress(ctx, network, address, s.spec.TLSConfig, remaining)
		if err == nil {
			return conn, nil
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *ExternalSupervisor) installConnection(conn net.Conn) {
	s.mu.Lock()
	s.conn = conn
	s.reader = bufio.NewReader(conn)
	s.writer = bufio.NewWriter(conn)
	s.mu.Unlock()
}

func (s *ExternalSupervisor) handshake(ctx context.Context) error {
	params := externalHandshake{
		ProtocolVersion: ExternalProtocolVersion, ModuleID: s.spec.ModuleID,
		RequiredCapabilities: s.spec.RequiredCapabilities,
	}
	raw, err := s.call(ctx, externalMethodHandshake, params)
	if err != nil {
		return err
	}
	var response externalHandshake
	if err := json.Unmarshal(raw, &response); err != nil {
		return fmt.Errorf("external module: invalid handshake response: %w", err)
	}
	if response.ProtocolVersion != ExternalProtocolVersion || response.ModuleID != s.spec.ModuleID {
		return errors.New("external module: handshake identity or protocol mismatch")
	}
	for _, required := range s.spec.RequiredCapabilities {
		if !hasExternalCapability(response.Capabilities, required) {
			return fmt.Errorf("external module: capability %q not advertised", required)
		}
	}
	return nil
}

// Ready asks the worker for an active readiness verdict. It does not publish
// a generation; callers that need blue/green behavior should wrap this client
// in Manager.Instance callbacks.
func (s *ExternalSupervisor) Ready(ctx context.Context) error {
	if s.isQuiescing() {
		return errors.New("external module: quiescing")
	}
	_, err := s.call(ctx, externalMethodReady, nil)
	return err
}

// Heartbeat performs the explicit liveness RPC. Hosts should call it on a
// bounded interval and withdraw readiness after a failed response.
func (s *ExternalSupervisor) Heartbeat(ctx context.Context) error {
	_, err := s.call(ctx, externalMethodHeartbeat, nil)
	return err
}

// Quiesce prevents new audit batches after the worker acknowledges the
// control-plane transition.
func (s *ExternalSupervisor) Quiesce(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.rpcMu.Lock()
	defer s.rpcMu.Unlock()
	if s.isQuiescing() {
		return nil
	}
	if _, err := s.callLocked(ctx, externalMethodQuiesce, nil); err != nil {
		return err
	}
	s.mu.Lock()
	s.quiescing = true
	s.mu.Unlock()
	return nil
}

// DeliverAuditBatch is the typed data-plane method. It refuses unbounded
// batches and refuses delivery after Quiesce, leaving retry policy to the host.
func (s *ExternalSupervisor) DeliverAuditBatch(ctx context.Context, events []audit.Event) error {
	if s == nil {
		return errors.New("external module: nil supervisor")
	}
	s.mu.RLock()
	quiescing, max := s.quiescing, s.spec.MaxBatchEvents
	s.mu.RUnlock()
	if quiescing {
		return errors.New("external module: quiescing")
	}
	if len(events) == 0 || len(events) > max {
		return fmt.Errorf("external module: audit batch size %d outside 1..%d", len(events), max)
	}
	s.rpcMu.Lock()
	defer s.rpcMu.Unlock()
	s.mu.RLock()
	quiescing = s.quiescing
	s.mu.RUnlock()
	if quiescing {
		return errors.New("external module: quiescing")
	}
	_, err := s.callLocked(ctx, externalMethodAuditBatch, externalAuditBatch{Events: events})
	return err
}

// Stop performs the typed shutdown handshake, closes the connection, waits
// for the child and removes only the socket path owned by this supervisor.
func (s *ExternalSupervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped, s.quiescing = true, true
	cmd, connected := s.cmd, s.conn != nil
	s.mu.Unlock()
	var result error
	if connected {
		_, result = s.call(ctx, externalMethodShutdown, nil)
	}
	s.closeConnection()
	if cmd != nil {
		result = errors.Join(result, waitExternalCommand(ctx, cmd))
	}
	cleanupExternalSocket(s.spec.SocketPath)
	return result
}

func (s *ExternalSupervisor) abortStart() {
	s.closeConnection()
	s.mu.Lock()
	cmd := s.cmd
	s.cmd = nil
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = waitExternalCommand(context.Background(), cmd)
	}
	cleanupExternalSocket(s.spec.SocketPath)
}

func waitExternalCommand(ctx context.Context, cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		return ctx.Err()
	}
}

func (s *ExternalSupervisor) closeConnection() {
	s.mu.Lock()
	conn := s.conn
	s.conn, s.reader, s.writer = nil, nil, nil
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func cleanupExternalSocket(path string) {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
}

func (s *ExternalSupervisor) isQuiescing() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.quiescing
}

func (s *ExternalSupervisor) call(ctx context.Context, method string, params any) ([]byte, error) {
	s.rpcMu.Lock()
	defer s.rpcMu.Unlock()
	return s.callLocked(ctx, method, params)
}

func (s *ExternalSupervisor) callLocked(ctx context.Context, method string, params any) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.RLock()
	conn, reader, writer := s.conn, s.reader, s.writer
	token, max, timeout := append([]byte(nil), s.spec.AuthToken...), s.spec.MaxFrameBytes, s.spec.RequestTimeout
	s.mu.RUnlock()
	if conn == nil || reader == nil || writer == nil {
		return nil, errors.New("external module: not connected")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("external module: encode %s: %w", method, err)
	}
	id := fmt.Sprintf("%d", s.requestID.Add(1))
	request := externalRequest{ID: id, Method: method, Token: hex.EncodeToString(token), Params: rawParams}
	if err := writeExternalMessage(writer, max, request); err != nil {
		return nil, fmt.Errorf("external module: write %s: %w", method, err)
	}
	var response externalResponse
	if err := readExternalMessage(reader, max, &response); err != nil {
		return nil, fmt.Errorf("external module: read %s: %w", method, err)
	}
	if response.ID != id {
		return nil, errors.New("external module: response id mismatch")
	}
	if !response.OK {
		return nil, fmt.Errorf("external module: %s failed: %s", method, response.Error)
	}
	return response.Result, nil
}

var _ ExternalAuditHandler = (*ExternalSupervisor)(nil)
var _ audit.Sink = (*ExternalSupervisor)(nil)
var _ Instance = (*ExternalSupervisor)(nil)
