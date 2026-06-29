package main

import (
	"fmt"
	"os"
)

const version = "v0.1.0"

func main() {
	cfg, err := loadConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("sso-mcp %s (transport=%s) — wiring lands in Task 5\n", version, cfg.Transport)
}
