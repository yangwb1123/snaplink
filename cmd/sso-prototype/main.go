package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/yangwb1123/snaplink/internal/composition"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(composition.Execute(
		ctx,
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		os.Getenv,
		edition,
		buildHandler,
	))
}
