// Package netpolicy is the network-classification control plane. Operators
// declare named classes of network (intranet, public, dmz, ...) with the
// CIDRs and hostnames that identify them; the SSO server (and any other
// service that imports the Classifier) decides at request time which class
// a caller belongs to and advertises class-appropriate URLs (JWKS, callback,
// logout) back in the response.
//
// Three layers:
//
//   - Store: persistence + Watch fan-out. Two backends: memory (in-process)
//     and etcd (distributed). Both implement the same Store interface.
//
//   - Classifier: keeps a priority-sorted snapshot of all policies and
//     answers Classify(remoteAddr, host) → *Policy synchronously. Subscribes
//     to the Store's Watch channel so updates are hot — no restart needed.
//
//   - HTTP + gRPC surfaces: live in netpolicy_handler.go and
//     grpcserver/netpolicy.go. They wrap a Store and a *audit.Recorder so
//     every Apply/Delete is captured as an audit event.
//
// Matching rules (in order):
//
//  1. Hostname match beats CIDR match. A request hitting sso.example.com
//     classifies as "public" even if its source IP is in 10.0.0.0/8.
//  2. Ties broken by Priority (higher wins).
//  3. CIDR match uses standard net.IPNet.Contains — no longest-prefix
//     resolution among multiple matching CIDRs of the same policy; instead,
//     the priority of the *policy* decides.
package netpolicy
