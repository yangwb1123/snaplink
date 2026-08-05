package legacysync

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

const passwordEnv = "SNAPLINK_LEGACY_DB_PASSWORD"

type stringMapFlag map[string]string

func (m stringMapFlag) String() string {
	parts := make([]string, 0, len(m))
	for key, value := range m {
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ",")
}

func (m stringMapFlag) Set(value string) error {
	key, mapped, ok := strings.Cut(value, "=")
	key = strings.TrimSpace(key)
	mapped = strings.TrimSpace(mapped)
	if !ok || key == "" || mapped == "" {
		return errors.New("mapping must be SOURCE=TARGET")
	}
	m[key] = mapped
	return nil
}

type commandConfig struct {
	SourceAddress string
	SourceUser    string
	SourceTLS     string
	TargetDSN     string
	Apply         bool
	Timeout       time.Duration
	AppMap        stringMapFlag
	RoleMap       stringMapFlag
	UserMap       stringMapFlag
}

func parseFlags(args []string, stderr io.Writer) (commandConfig, error) {
	cfg := commandConfig{AppMap: stringMapFlag{}, RoleMap: stringMapFlag{}, UserMap: stringMapFlag{}}
	fs := flag.NewFlagSet("sso-ctl legacy-sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.SourceAddress, "source-address", "192.168.123.51:3306", "legacy MySQL host:port")
	fs.StringVar(&cfg.SourceUser, "source-user", "root", "legacy MySQL user")
	fs.StringVar(&cfg.SourceTLS, "source-tls", "skip-verify", "MySQL TLS mode")
	fs.StringVar(&cfg.TargetDSN, "target-dsn", "", "Snaplink SQLite DSN")
	fs.BoolVar(&cfg.Apply, "apply", false, "write the plan; omission is dry-run")
	fs.DurationVar(&cfg.Timeout, "timeout", 2*time.Minute, "whole operation timeout")
	fs.Var(cfg.AppMap, "app-map", "repeatable SOURCE_APP=TARGET_CLIENT mapping")
	fs.Var(cfg.RoleMap, "role-map", "repeatable APP:ROLE=TARGET_ROLE mapping")
	fs.Var(cfg.UserMap, "user-map", "repeatable SOURCE_LOGIN=TARGET_USER mapping")
	if err := fs.Parse(args); err != nil {
		return commandConfig{}, err
	}
	if cfg.TargetDSN == "" {
		return commandConfig{}, errors.New("--target-dsn is required")
	}
	if cfg.SourceAddress == "" || cfg.SourceUser == "" {
		return commandConfig{}, errors.New("source address and user are required")
	}
	if cfg.Timeout <= 0 {
		return commandConfig{}, errors.New("--timeout must be positive")
	}
	for key := range cfg.RoleMap {
		app, _, ok := strings.Cut(key, ":")
		if !ok || cfg.AppMap[app] == "" {
			return commandConfig{}, fmt.Errorf("--role-map %q references an unmapped app", key)
		}
	}
	return cfg, nil
}
