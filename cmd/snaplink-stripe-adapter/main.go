package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

const (
	startupTimeout    = 30 * time.Second
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 64 * 1024
)

type adapterApplication struct {
	config  runtimeConfig
	handler http.Handler
	store   *adapterStore
	jwks    *rs.JWKSCache
	worker  *relayWorker
	logger  *log.Logger
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Stderr, os.Getenv))
}

func execute(ctx context.Context, stderr io.Writer, getenv func(string) string) int {
	config, err := loadConfig(getenv)
	if err != nil {
		fmt.Fprintf(stderr, "%s: configuration rejected: %v\n", programName, err)
		return 2
	}
	app, err := buildAdapterApplication(config, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%s: startup failed: %v\n", programName, err)
		return 1
	}
	defer app.Close()
	if err := app.Serve(ctx); err != nil {
		fmt.Fprintf(stderr, "%s: stopped with error: %v\n", programName, err)
		return 1
	}
	return 0
}

func buildAdapterApplication(config runtimeConfig, stderr io.Writer) (*adapterApplication, error) {
	store, err := openAdapterStore(config)
	if err != nil {
		return nil, errors.New("open database failed")
	}
	startupCtx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	if err := store.Migrate(startupCtx); err != nil {
		_ = store.Close()
		return nil, errors.New("database migration failed")
	}
	client := newOutboundHTTPClient(config.HTTPTimeout)
	jwks := rs.NewJWKSCache(config.JWKSURL, remote.WithJWKSHTTPClient(client))
	billing := newBillingClient(config, client)
	metrics := &adapterMetrics{}
	handler, err := newAdapterHandler(config, store, newStripeClient(config, client), billing, jwks, client, metrics)
	if err != nil {
		jwks.Close()
		_ = store.Close()
		return nil, err
	}
	logger := log.New(stderr, programName+": ", log.LstdFlags|log.LUTC)
	worker := newRelayWorker(config, store, billing, newRelayOwner(), logger, metrics)
	return &adapterApplication{config: config, handler: handler, store: store, jwks: jwks, worker: worker, logger: logger}, nil
}

func newOutboundHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 20
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func newRelayOwner() string {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("stripe-adapter:%d:%d", os.Getpid(), time.Now().UnixNano())
	}
	return fmt.Sprintf("stripe-adapter:%d:%s", os.Getpid(), hex.EncodeToString(random))
}

func (a *adapterApplication) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", a.config.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	server := a.newHTTPServer()
	workerCtx, stopWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); a.worker.Run(workerCtx) }()
	serveDone := make(chan error, 1)
	go func() { serveDone <- a.serveHTTP(server, listener) }()
	a.logger.Printf("listening address=%s", listener.Addr())
	select {
	case err := <-serveDone:
		stopWorker()
		<-workerDone
		return normalizeServerError(err)
	case <-ctx.Done():
		return a.gracefulStop(server, serveDone, stopWorker, workerDone)
	}
}

func (a *adapterApplication) newHTTPServer() *http.Server {
	writeTimeout := a.config.HandlerTimeout + 5*time.Second
	return &http.Server{
		Addr: a.config.Listen, Handler: a.handler,
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout,
		WriteTimeout: writeTimeout, IdleTimeout: idleTimeout,
		MaxHeaderBytes: maxHeaderBytes, ErrorLog: a.logger,
	}
}

func (a *adapterApplication) serveHTTP(server *http.Server, listener net.Listener) error {
	if a.config.TLSCertFile != "" {
		return server.ServeTLS(listener, a.config.TLSCertFile, a.config.TLSKeyFile)
	}
	return server.Serve(listener)
}

func (a *adapterApplication) gracefulStop(
	server *http.Server, serveDone <-chan error, stopWorker context.CancelFunc, workerDone <-chan struct{},
) error {
	serverCtx, cancelServer := context.WithTimeout(context.Background(), a.config.ShutdownDrain)
	serverErr := server.Shutdown(serverCtx)
	cancelServer()
	stopWorker()
	drain := time.NewTimer(a.config.ShutdownDrain)
	defer drain.Stop()
	select {
	case <-workerDone:
	case <-drain.C:
		return errors.Join(serverErr, errors.New("relay drain deadline exceeded"))
	}
	return errors.Join(serverErr, normalizeServerError(<-serveDone))
}

func normalizeServerError(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *adapterApplication) Close() {
	a.jwks.Close()
	_ = a.store.Close()
}
