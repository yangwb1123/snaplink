// Package registry models service registration & discovery for microservice
// deployments. The Registry interface is backend-agnostic; concrete drivers
// (in-memory, etcd, consul) live in sub-packages so each backend's external
// dependency only enters go.mod when you import that sub-package.
//
// Typical use:
//
//	reg, _ := etcd.New(etcd.Config{Endpoints: []string{"localhost:2379"}})
//	defer reg.Close()
//	reg.Register(ctx, &registry.Service{
//	    ID: "sso-1", Name: "sso", Address: "10.0.0.1", Port: 8080,
//	    TTL: 30 * time.Second,
//	})
//	instances, _ := reg.Discover(ctx, "sso")
//
// The registry has zero dependency on the sso package.
package registry
