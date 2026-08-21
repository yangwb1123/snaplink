package modules

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/yangwb1123/snaplink/platform/audit"
)

type externalRequest struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Token  string          `json:"token"`
	Params json.RawMessage `json:"params,omitempty"`
}

type externalResponse struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

type externalHandshake struct {
	ProtocolVersion      uint32               `json:"protocol_version"`
	ModuleID             string               `json:"module_id"`
	RequiredCapabilities []ExternalCapability `json:"required_capabilities,omitempty"`
	Capabilities         []ExternalCapability `json:"capabilities,omitempty"`
}

type externalAuditBatch struct {
	Events []audit.Event `json:"events"`
}

// ServeExternalConnection is the worker-side protocol loop. The caller owns
// listener creation and process policy; this function only authenticates and
// dispatches the fixed control/data methods.
func ServeExternalConnection(ctx context.Context, conn net.Conn, options ExternalServerOptions, handler ExternalAuditHandler) error {
	normalized, err := normalizeExternalServerOptions(options, handler)
	if err != nil {
		return err
	}
	if conn == nil {
		return errors.New("external module: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer conn.Close()
	closed := make(chan struct{})
	go closeExternalConnectionOnContext(ctx, conn, closed)
	defer close(closed)
	return serveExternalLoop(ctx, conn, normalized, handler)
}

func normalizeExternalServerOptions(options ExternalServerOptions, handler ExternalAuditHandler) (ExternalServerOptions, error) {
	if strings.TrimSpace(options.ModuleID) == "" || len(options.AuthToken) == 0 || handler == nil {
		return ExternalServerOptions{}, errors.New("external module: invalid server options")
	}
	if options.ProtocolVersion == 0 {
		options.ProtocolVersion = ExternalProtocolVersion
	}
	if options.MaxFrameBytes <= 0 {
		options.MaxFrameBytes = defaultExternalFrameBytes
	}
	if options.MaxBatchEvents <= 0 {
		options.MaxBatchEvents = defaultExternalBatchEvents
	}
	if options.MaxFrameBytes > maxExternalFrameBytes || options.MaxBatchEvents > maxExternalBatchEvents {
		return ExternalServerOptions{}, errors.New("external module: size limit exceeds safety bound")
	}
	if options.ProtocolVersion != ExternalProtocolVersion || !hasExternalCapability(options.Capabilities, ExternalCapabilityAuditBatch) {
		return ExternalServerOptions{}, errors.New("external module: server protocol or capability is unsupported")
	}
	return options, nil
}

func closeExternalConnectionOnContext(ctx context.Context, conn net.Conn, closed <-chan struct{}) {
	select {
	case <-ctx.Done():
		_ = conn.Close()
	case <-closed:
	}
}

func serveExternalLoop(ctx context.Context, conn net.Conn, options ExternalServerOptions, handler ExternalAuditHandler) error {
	reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
	session := externalSession{}
	for {
		stop, err := session.serveOne(ctx, reader, writer, options, handler)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
}

type externalSession struct {
	authenticated bool
	quiescing     bool
}

func (s *externalSession) serveOne(ctx context.Context, reader *bufio.Reader, writer *bufio.Writer, options ExternalServerOptions, handler ExternalAuditHandler) (bool, error) {
	var request externalRequest
	if err := readExternalMessage(reader, options.MaxFrameBytes, &request); err != nil {
		if errors.Is(err, io.EOF) || ctx.Err() != nil {
			return true, nil
		}
		return true, err
	}
	result, stop, err := s.dispatch(ctx, request, options, handler)
	if writeErr := writeExternalResponse(writer, options.MaxFrameBytes, request.ID, result, err); writeErr != nil {
		return true, writeErr
	}
	if err != nil && (!s.authenticated || !secureHexEqual(request.Token, hex.EncodeToString(options.AuthToken))) {
		return true, err
	}
	return stop, nil
}

func (s *externalSession) dispatch(ctx context.Context, request externalRequest, options ExternalServerOptions, handler ExternalAuditHandler) (any, bool, error) {
	if !s.authenticated {
		result, err := authenticateExternalRequest(request, options)
		if err == nil {
			s.authenticated = true
		}
		return result, false, err
	}
	if !secureHexEqual(request.Token, hex.EncodeToString(options.AuthToken)) {
		return nil, false, errors.New("external module: authentication failed")
	}
	result, stop, quiescing, err := dispatchExternalRequest(ctx, request, options, handler, s.quiescing)
	s.quiescing = quiescing
	return result, stop, err
}

func authenticateExternalRequest(request externalRequest, options ExternalServerOptions) (any, error) {
	if request.Method != externalMethodHandshake || !secureHexEqual(request.Token, hex.EncodeToString(options.AuthToken)) {
		return nil, errors.New("external module: authentication failed")
	}
	var hello externalHandshake
	if err := json.Unmarshal(request.Params, &hello); err != nil {
		return nil, errors.New("external module: invalid handshake request")
	}
	if hello.ProtocolVersion != ExternalProtocolVersion || hello.ModuleID != options.ModuleID {
		return nil, errors.New("external module: handshake identity or protocol mismatch")
	}
	for _, required := range hello.RequiredCapabilities {
		if !hasExternalCapability(options.Capabilities, required) {
			return nil, fmt.Errorf("external module: capability %q unavailable", required)
		}
	}
	return externalHandshake{ProtocolVersion: ExternalProtocolVersion, ModuleID: options.ModuleID, Capabilities: options.Capabilities}, nil
}

func dispatchExternalRequest(ctx context.Context, request externalRequest, options ExternalServerOptions, handler ExternalAuditHandler, quiescing bool) (any, bool, bool, error) {
	if request.Method == externalMethodAuditBatch {
		return dispatchExternalAuditBatch(ctx, request, options, handler, quiescing)
	}
	return dispatchExternalControl(ctx, request.Method, options, quiescing)
}

func dispatchExternalControl(ctx context.Context, method string, options ExternalServerOptions, quiescing bool) (any, bool, bool, error) {
	switch method {
	case externalMethodReady:
		return dispatchExternalReady(ctx, options, quiescing)
	case externalMethodHeartbeat:
		return dispatchExternalHeartbeat(ctx, options, quiescing)
	case externalMethodQuiesce:
		return dispatchExternalQuiesce(ctx, options, quiescing)
	case externalMethodShutdown:
		return dispatchExternalShutdown(ctx, options, quiescing)
	default:
		return nil, false, quiescing, errors.New("external module: unsupported method")
	}
}

func dispatchExternalReady(ctx context.Context, options ExternalServerOptions, quiescing bool) (any, bool, bool, error) {
	if quiescing {
		return nil, false, quiescing, errors.New("external module: quiescing")
	}
	if options.Ready == nil {
		return nil, false, quiescing, nil
	}
	return nil, false, quiescing, options.Ready(ctx)
}

func dispatchExternalHeartbeat(ctx context.Context, options ExternalServerOptions, quiescing bool) (any, bool, bool, error) {
	if options.Heartbeat == nil {
		return nil, false, quiescing, nil
	}
	return nil, false, quiescing, options.Heartbeat(ctx)
}

func dispatchExternalQuiesce(ctx context.Context, options ExternalServerOptions, quiescing bool) (any, bool, bool, error) {
	if options.Quiesce == nil {
		return nil, false, true, nil
	}
	if err := options.Quiesce(ctx); err != nil {
		return nil, false, quiescing, err
	}
	return nil, false, true, nil
}

func dispatchExternalShutdown(ctx context.Context, options ExternalServerOptions, quiescing bool) (any, bool, bool, error) {
	if options.Shutdown == nil {
		return nil, true, quiescing, nil
	}
	return nil, true, quiescing, options.Shutdown(ctx)
}

func dispatchExternalAuditBatch(ctx context.Context, request externalRequest, options ExternalServerOptions, handler ExternalAuditHandler, quiescing bool) (any, bool, bool, error) {
	if quiescing {
		return nil, false, quiescing, errors.New("external module: quiescing")
	}
	var batch externalAuditBatch
	if err := json.Unmarshal(request.Params, &batch); err != nil || len(batch.Events) == 0 || len(batch.Events) > options.MaxBatchEvents {
		return nil, false, quiescing, errors.New("external module: invalid audit batch")
	}
	return nil, false, quiescing, handler.DeliverAuditBatch(ctx, batch.Events)
}

func writeExternalResponse(writer *bufio.Writer, max int, id string, result any, callErr error) error {
	response := externalResponse{ID: id, OK: callErr == nil}
	if callErr != nil {
		response.Error = callErr.Error()
	} else if result != nil {
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		response.Result = raw
	}
	return writeExternalMessage(writer, max, response)
}

func readExternalMessage(reader *bufio.Reader, max int, target any) error {
	var frame []byte
	for {
		part, err := reader.ReadSlice('\n')
		frame = append(frame, part...)
		if len(frame) > max {
			return errors.New("external module: frame exceeds limit")
		}
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return err
		}
	}
	return json.Unmarshal(bytes.TrimSpace(frame), target)
}

func writeExternalMessage(writer *bufio.Writer, max int, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw)+1 > max {
		return errors.New("external module: frame exceeds limit")
	}
	if _, err := writer.Write(raw); err != nil {
		return err
	}
	if err := writer.WriteByte('\n'); err != nil {
		return err
	}
	return writer.Flush()
}

func hasExternalCapability(capabilities []ExternalCapability, wanted ExternalCapability) bool {
	for _, capability := range capabilities {
		if capability == wanted {
			return true
		}
	}
	return false
}

func secureHexEqual(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftHash, rightHash := sha256.Sum256(leftBytes), sha256.Sum256(rightBytes)
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

// Record adapts the typed audit-batch capability to audit.Sink. The worker is
// a fail-open tap: callers decide whether delivery errors are observable.
func (s *ExternalSupervisor) Record(ctx context.Context, event *audit.Event) error {
	if event == nil {
		return nil
	}
	return s.DeliverAuditBatch(ctx, []audit.Event{*event})
}

func (s *ExternalSupervisor) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

func (s *ExternalSupervisor) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}
