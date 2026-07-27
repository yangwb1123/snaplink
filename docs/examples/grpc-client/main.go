// examples/grpc-client demonstrates calling all three Phase A gRPC services
// against a running cmd/sso-server. Run cmd/sso-server first (default
// gRPC listener is :8081), then:
//
//	go run ./examples/grpc-client                 # default :8081
//	go run ./examples/grpc-client --addr :9091    # custom
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	auditv1 "github.com/yangwb1123/snaplink/gen/proto/audit/v1"
	authzv1 "github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	discoveryv1 "github.com/yangwb1123/snaplink/gen/proto/discovery/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("addr", "localhost:8081", "sso-server gRPC address")
	flag.Parse()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	demoAuthz(ctx, conn)
	demoDiscovery(ctx, conn)
	demoAudit(ctx, conn)
}

func demoAuthz(ctx context.Context, conn *grpc.ClientConn) {
	c := authzv1.NewAuthorizerClient(conn)

	check := func(perm string) {
		resp, err := c.Check(ctx, &authzv1.CheckRequest{
			SubjectId: "user-alice", ClientId: "web-app", Permission: perm,
		})
		if err != nil {
			fmt.Printf("authz Check(%q): %v\n", perm, err)
			return
		}
		fmt.Printf("authz Check(%q) → allowed=%v\n", perm, resp.Allowed)
	}
	check("user:read")
	check("user:create")
	check("audit:read")

	tree, err := c.GetMenus(ctx, &authzv1.SubjectRequest{SubjectId: "user-alice", ClientId: "web-app"})
	if err != nil {
		fmt.Printf("authz GetMenus: %v\n", err)
		return
	}
	fmt.Printf("authz GetMenus → %d top-level items\n", len(tree.Items))
	for _, m := range tree.Items {
		fmt.Printf("  • %s (%s)\n", m.Name, m.Path)
	}
}

func demoDiscovery(ctx context.Context, conn *grpc.ClientConn) {
	c := discoveryv1.NewDiscoveryClient(conn)

	resp, err := c.Discover(ctx, &discoveryv1.DiscoverRequest{ServiceName: "sso"})
	if err != nil {
		fmt.Printf("discovery Discover(sso): %v\n", err)
		return
	}
	fmt.Printf("discovery Discover(sso) → %d instances\n", len(resp.Instances))
	for _, s := range resp.Instances {
		fmt.Printf("  • %s @ %s:%d\n", s.Id, s.Address, s.Port)
	}
}

func demoAudit(ctx context.Context, conn *grpc.ClientConn) {
	c := auditv1.NewAuditWriterClient(conn)

	stream, err := c.StreamEvents(ctx)
	if err != nil {
		fmt.Printf("audit StreamEvents open: %v\n", err)
		return
	}
	for i := range 3 {
		_ = stream.Send(&auditv1.Event{
			Type:      "demo_event",
			Outcome:   "success",
			ActorId:   "demo-client",
			RequestId: fmt.Sprintf("demo-%d", i),
		})
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		fmt.Printf("audit StreamEvents close: %v\n", err)
		return
	}
	fmt.Printf("audit StreamEvents → received=%d persisted=%d\n", ack.ReceivedCount, ack.PersistedCount)
}
