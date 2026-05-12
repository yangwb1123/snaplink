package registry

import "time"

// Service is one instance of a logical service. Multiple instances share
// Name; each gets a unique ID so deregistration is targetable.
type Service struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Address  string            `json:"address"`
	Port     int               `json:"port"`
	Tags     []string          `json:"tags,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Version  string            `json:"version,omitempty"`

	// HealthCheck, when set, instructs backends that support active probing
	// (consul) to monitor this instance. Backends without active checks
	// (etcd) ignore this field and rely on TTL renewal.
	HealthCheck *HealthCheck `json:"health_check,omitempty"`

	// TTL declares how long the registration should survive without a
	// renewal/heartbeat. Backends interpret this:
	//   - etcd: lease lifetime; KeepAlive runs at TTL/3.
	//   - memory: cleanup goroutine prunes expired entries.
	//   - consul: registers a TTL check; the backend renews automatically.
	// Zero TTL means "no expiration" (backend-dependent semantics).
	TTL time.Duration `json:"ttl,omitempty"`
}

// HealthCheck describes how a backend should probe the instance for liveness.
// Only one mode is set per check (HTTP, TCP, or GRPC).
type HealthCheck struct {
	HTTP     string        `json:"http,omitempty"`
	TCP      string        `json:"tcp,omitempty"`
	GRPC     string        `json:"grpc,omitempty"`
	Interval time.Duration `json:"interval,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

// EventType discriminates the kind of change a Watch reports.
type EventType string

const (
	EventAdded   EventType = "added"
	EventRemoved EventType = "removed"
	EventUpdated EventType = "updated"
)

// Event is one change observed in a Watch stream.
type Event struct {
	Type    EventType
	Service *Service
}

// Endpoint is the host:port form of a Service. Helper for client load balancers.
func (s *Service) Endpoint() string {
	if s.Port == 0 {
		return s.Address
	}
	return s.Address + ":" + itoa(s.Port)
}

// itoa avoids importing strconv just for one int-to-string call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
