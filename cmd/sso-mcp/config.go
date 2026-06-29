package main

import (
	"flag"
	"fmt"
	"strings"
)

const (
	transportHTTP  = "http"
	transportStdio = "stdio"

	defaultListen        = ":8090"
	defaultSnaplinkGRPC  = "localhost:8081"
	defaultRequiredScope = "mcp:read"
)

// Config is the runtime configuration, sourced from flags then env (flag wins).
// It deliberately avoids the parent SSO config package: this module needs ~7
// fields, not the server's 50-struct config.
type Config struct {
	Transport     string // http | stdio
	Listen        string // HTTP bind (http transport only)
	SnaplinkGRPC  string // snaplink Authorizer gRPC address
	JWKSURL       string // snaplink JWKS endpoint (token validation; needed in both transports)
	Issuer        string // snaplink issuer (PRM authorization_servers)
	ResourceURI   string // this server's canonical URI / required aud (http gate)
	RequiredScope string // required scope in agent tokens (http gate)
}

func loadConfig(args []string, getenv func(string) string) (*Config, error) {
	fs := flag.NewFlagSet("sso-mcp", flag.ContinueOnError)
	c := &Config{}
	fs.StringVar(&c.Transport, "transport", "", "http | stdio (env SSO_MCP_TRANSPORT)")
	fs.StringVar(&c.Listen, "listen", "", "HTTP listen address (env SSO_MCP_LISTEN)")
	fs.StringVar(&c.SnaplinkGRPC, "snaplink-grpc", "", "snaplink Authorizer gRPC addr (env SSO_MCP_SNAPLINK_GRPC)")
	fs.StringVar(&c.JWKSURL, "jwks-url", "", "snaplink JWKS URL (env SSO_MCP_JWKS_URL)")
	fs.StringVar(&c.Issuer, "issuer", "", "snaplink issuer URL (env SSO_MCP_ISSUER)")
	fs.StringVar(&c.ResourceURI, "resource", "", "this server's resource URI / required aud (env SSO_MCP_RESOURCE)")
	fs.StringVar(&c.RequiredScope, "required-scope", "", "required token scope (env SSO_MCP_REQUIRED_SCOPE)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	fillFromEnv(c, getenv)
	fillDefaults(c)
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func fillFromEnv(c *Config, getenv func(string) string) {
	set := func(dst *string, key string) {
		if *dst == "" {
			*dst = getenv(key)
		}
	}
	set(&c.Transport, "SSO_MCP_TRANSPORT")
	set(&c.Listen, "SSO_MCP_LISTEN")
	set(&c.SnaplinkGRPC, "SSO_MCP_SNAPLINK_GRPC")
	set(&c.JWKSURL, "SSO_MCP_JWKS_URL")
	set(&c.Issuer, "SSO_MCP_ISSUER")
	set(&c.ResourceURI, "SSO_MCP_RESOURCE")
	set(&c.RequiredScope, "SSO_MCP_REQUIRED_SCOPE")
}

func fillDefaults(c *Config) {
	if c.Transport == "" {
		c.Transport = transportHTTP
	}
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if c.SnaplinkGRPC == "" {
		c.SnaplinkGRPC = defaultSnaplinkGRPC
	}
	if c.RequiredScope == "" {
		c.RequiredScope = defaultRequiredScope
	}
}

func (c *Config) validate() error {
	if c.Transport != transportHTTP && c.Transport != transportStdio {
		return fmt.Errorf("invalid transport %q (want http|stdio)", c.Transport)
	}
	if strings.TrimSpace(c.JWKSURL) == "" {
		return fmt.Errorf("jwks-url is required (token validation)")
	}
	if c.Transport == transportHTTP && strings.TrimSpace(c.ResourceURI) == "" {
		return fmt.Errorf("resource is required for http transport (token aud)")
	}
	return nil
}
