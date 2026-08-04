package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 15 * time.Second
	maxHeaderBytes    = 1 << 20
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func execute(
	ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string,
) int {
	if handled, code := handleCommand(args, stdout, stderr); handled {
		return code
	}
	config, err := parseRuntimeConfig(args, getenv, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: config: %v\n", programName, err)
		return 2
	}
	app, err := buildApplication(config)
	if err != nil {
		fmt.Fprintf(stderr, "%s: build: %v\n", programName, err)
		return 1
	}
	backgroundCtx, cancelBackground := context.WithCancel(ctx)
	waitBackground := app.startBackground(backgroundCtx, stderr)
	err = serve(ctx, config.Listen, app.handler, stderr)
	cancelBackground()
	waitBackground()
	if closeErr := app.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", programName, err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, address string, handler http.Handler, stderr io.Writer) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen %s: %w", address, err)
	}
	server := newHTTPServer(address, handler, stderr)
	fmt.Fprintf(stderr, "%s: listening on %s\n", programName, listener.Addr())
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		return normalizeServeError(err)
	case <-ctx.Done():
		return stopServer(server, done)
	}
}

func newHTTPServer(address string, handler http.Handler, stderr io.Writer) *http.Server {
	return &http.Server{
		Addr: address, Handler: handler,
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout,
		WriteTimeout: writeTimeout, IdleTimeout: idleTimeout,
		MaxHeaderBytes: maxHeaderBytes, ErrorLog: log.New(stderr, programName+": ", 0),
	}
}

func stopServer(server *http.Server, done <-chan error) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return normalizeServeError(<-done)
}

func normalizeServeError(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
