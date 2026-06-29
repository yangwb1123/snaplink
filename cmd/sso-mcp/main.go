package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "v0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := loadConfig(args, os.Getenv)
	if err != nil {
		return err
	}
	sc, err := newSnaplinkClient(cfg)
	if err != nil {
		return err
	}
	defer sc.Close()

	srv := newMCPServer(&toolDeps{intro: sc.auth, authz: sc.authz})
	if cfg.Transport == transportStdio {
		return srv.Run(context.Background(), &mcp.StdioTransport{})
	}
	return serveHTTP(srv, sc, cfg)
}

func serveHTTP(srv *mcp.Server, sc *snaplinkClient, cfg *Config) error {
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           buildHTTPHandler(srv, sc, cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-sigCh:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return httpSrv.Shutdown(ctx)
}
