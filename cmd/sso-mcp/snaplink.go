package main

import (
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// snaplinkClient bundles the two remote clients sso-mcp needs: local token
// validation (AuthClient over a JWKS cache) and authorization queries
// (AuthzClient over a gRPC conn to snaplink's OPEN Authorizer service —
// no credentials are required for it by design).
type snaplinkClient struct {
	auth  *remote.AuthClient
	authz *remote.AuthzClient
	jwks  *remote.JWKSCache
	conn  *grpc.ClientConn
}

func newSnaplinkClient(cfg *Config) (*snaplinkClient, error) {
	jwks := remote.NewJWKSCache(cfg.JWKSURL, remote.WithJWKSRefreshInterval(time.Hour))
	// grpc.NewClient is lazy: it does not connect here, so an unreachable
	// address does not fail startup (it fails on first RPC instead).
	conn, err := grpc.NewClient(cfg.SnaplinkGRPC,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		jwks.Close()
		return nil, err
	}
	return &snaplinkClient{
		auth:  remote.NewAuthClient(jwks),
		authz: remote.NewAuthzClient(conn),
		jwks:  jwks,
		conn:  conn,
	}, nil
}

func (c *snaplinkClient) Close() error {
	c.jwks.Close()
	return c.conn.Close()
}
