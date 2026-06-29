package main

import (
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newMCPServer(d *toolDeps) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "sso-mcp", Version: version}, nil)
	registerTools(s, d)
	return s
}

// mcpMux mounts the gated /mcp endpoint plus PRM and livez. readyz is added by
// buildHTTPHandler, which has the live *snaplinkClient it needs.
func mcpMux(s *mcp.Server, intro introspector, cfg *Config) *http.ServeMux {
	mux := http.NewServeMux()
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	mux.Handle(pathMCP, newRSGate(intro, cfg, streamable))
	mux.HandleFunc(pathPRM, prmHandler(cfg))
	mux.HandleFunc(pathLivez, livezHandler())
	return mux
}

func buildHTTPHandler(s *mcp.Server, sc *snaplinkClient, cfg *Config) http.Handler {
	mux := mcpMux(s, sc.auth, cfg)
	mux.HandleFunc(pathReadyz, readyzHandler(sc))
	return mux
}
