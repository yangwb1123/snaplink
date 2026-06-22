package redis

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Options is the backend-agnostic connection config for NewUniversalClient. It
// mirrors the operator-facing config block but carries no dependency on the
// core config package, so the redis module stays importable on its own. The
// caller (cmd) maps its config.RedisConfig onto this.
type Options struct {
	// Mode selects the client topology: "single" (default), "sentinel", or
	// "cluster". Empty infers from the other fields (MasterName -> sentinel,
	// >1 Addr -> cluster, else single) to match goredis.NewUniversalClient.
	Mode  string
	Addrs []string

	Username   string
	Password   string
	DB         int    // single/sentinel only; cluster requires 0
	MasterName string // required for sentinel

	PoolSize        int
	MinIdleConns    int
	MaxRetries      int
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	PoolTimeout     time.Duration
	ConnMaxIdleTime time.Duration
	ConnMaxLifetime time.Duration

	// RouteByLatency / RouteRandomly / ReadOnly apply to cluster + failover-
	// cluster topologies; they spread reads across replicas. Leave them OFF for
	// the single-use/replay stores (auth_code, refresh, jti) — replica lag could
	// let a replay momentarily evade detection; keep those master-pinned.
	RouteByLatency bool
	RouteRandomly  bool
	ReadOnly       bool

	TLS *TLSOptions
}

// TLSOptions configures an optional TLS transport to Redis. Enabled=false (the
// zero value) means a plaintext connection.
type TLSOptions struct {
	Enabled            bool
	CAFile             string
	CertFile           string
	KeyFile            string
	ServerName         string
	InsecureSkipVerify bool
}

const (
	modeSingle   = "single"
	modeSentinel = "sentinel"
	modeCluster  = "cluster"
)

// resolveMode applies the documented inference for an empty Mode.
func (o Options) resolveMode() string {
	m := strings.ToLower(strings.TrimSpace(o.Mode))
	if m != "" {
		return m
	}
	switch {
	case o.MasterName != "":
		return modeSentinel
	case len(o.Addrs) > 1:
		return modeCluster
	default:
		return modeSingle
	}
}

// validate rejects mode/field combinations that would fail or silently
// misbehave at runtime, turning operator mistakes into loud boot errors.
func (o Options) validate(mode string) error {
	if len(o.Addrs) == 0 {
		return errors.New("redis: at least one addr is required")
	}
	switch mode {
	case modeSentinel:
		if o.MasterName == "" {
			return errors.New("redis: sentinel mode requires master_name")
		}
	case modeCluster:
		if o.DB != 0 {
			// Redis Cluster has a single logical DB (0); a non-zero db is a
			// config error that would otherwise be silently dropped.
			return errors.New("redis: cluster mode requires db=0")
		}
	case modeSingle:
	default:
		return fmt.Errorf("redis: unknown mode %q (supported: single, sentinel, cluster)", mode)
	}
	return nil
}

// NewUniversalClient builds a go-redis client for single, sentinel, or cluster
// Redis from one Options. The returned goredis.UniversalClient is exactly the
// interface every store constructor already accepts (it embeds Cmdable), so the
// same store code runs against any topology with no per-store change. The
// caller owns Close.
func NewUniversalClient(o Options) (goredis.UniversalClient, error) {
	mode := o.resolveMode()
	if err := o.validate(mode); err != nil {
		return nil, err
	}

	tlsCfg, err := o.tlsConfig()
	if err != nil {
		return nil, err
	}

	uo := &goredis.UniversalOptions{
		Addrs:           o.Addrs,
		Username:        o.Username,
		Password:        o.Password,
		DB:              o.DB,
		MasterName:      o.MasterName,
		PoolSize:        o.PoolSize,
		MinIdleConns:    o.MinIdleConns,
		MaxRetries:      o.MaxRetries,
		DialTimeout:     o.DialTimeout,
		ReadTimeout:     o.ReadTimeout,
		WriteTimeout:    o.WriteTimeout,
		PoolTimeout:     o.PoolTimeout,
		ConnMaxIdleTime: o.ConnMaxIdleTime,
		ConnMaxLifetime: o.ConnMaxLifetime,
		RouteByLatency:  o.RouteByLatency,
		RouteRandomly:   o.RouteRandomly,
		ReadOnly:        o.ReadOnly,
		TLSConfig:       tlsCfg,
	}

	// Dispatch explicitly on the resolved mode rather than relying on
	// NewUniversalClient's inference, so an operator who declares mode:cluster
	// with a single seed addr still gets a ClusterClient (inference would pick
	// single). The .Cluster()/.Failover()/.Simple() converters drop the fields
	// the chosen topology doesn't use.
	switch mode {
	case modeCluster:
		return goredis.NewClusterClient(uo.Cluster()), nil
	case modeSentinel:
		return goredis.NewFailoverClient(uo.Failover()), nil
	default:
		return goredis.NewClient(uo.Simple()), nil
	}
}

// tlsConfig builds the *tls.Config from TLSOptions, or nil when TLS is off.
func (o Options) tlsConfig() (*tls.Config, error) {
	if o.TLS == nil || !o.TLS.Enabled {
		return nil, nil
	}
	cfg := &tls.Config{
		ServerName:         o.TLS.ServerName,
		InsecureSkipVerify: o.TLS.InsecureSkipVerify, //nolint:gosec // operator opt-in for self-signed dev clusters; documented as insecure
		MinVersion:         tls.VersionTLS12,
	}
	if o.TLS.CAFile != "" {
		pem, err := os.ReadFile(o.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("redis: read tls ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("redis: tls ca_file %q contained no certificates", o.TLS.CAFile)
		}
		cfg.RootCAs = pool
	}
	if o.TLS.CertFile != "" || o.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(o.TLS.CertFile, o.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("redis: load tls client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
