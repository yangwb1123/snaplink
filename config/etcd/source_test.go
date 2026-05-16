package etcd

// Pure-logic tests only — no etcd server required. Integration tests
// against a real etcd would live behind a build tag. Covers:
//   * parseKey under various prefix shapes (with/without trailing slash,
//     keys outside the prefix, the bare-prefix key, empty segments)
//   * buildConfigMap merges multiple KVs into a nested tree and coerces
//     value types via parse.Value
//   * Source.Name formatting
//   * New rejects empty endpoints (mirrors netpolicy/etcd convention)
//   * NewWithClient honors empty prefix → DefaultPrefix

import (
	"reflect"
	"testing"
)

func TestParseKey_BasicNested(t *testing.T) {
	got := parseKey("/snaplink/config", "/snaplink/config/server/listen")
	want := []string{"server", "listen"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKey = %v, want %v", got, want)
	}
}

func TestParseKey_PrefixWithTrailingSlash(t *testing.T) {
	got := parseKey("/snaplink/config/", "/snaplink/config/server/listen")
	want := []string{"server", "listen"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKey (trailing-slash prefix) = %v, want %v", got, want)
	}
}

func TestParseKey_LowercasesSegments(t *testing.T) {
	got := parseKey("/snaplink/config", "/snaplink/config/Server/Listen")
	want := []string{"server", "listen"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKey did not lowercase: %v", got)
	}
}

func TestParseKey_NotUnderPrefix(t *testing.T) {
	if got := parseKey("/snaplink/config", "/other/key"); got != nil {
		t.Errorf("expected nil for off-prefix key, got %v", got)
	}
}

func TestParseKey_PrefixCollisionBoundary(t *testing.T) {
	// "/snaplink/configX/foo" should NOT match prefix "/snaplink/config"
	// — the trailing-slash boundary is what etcd's own WithPrefix gets
	// wrong if you don't enforce it.
	if got := parseKey("/snaplink/config", "/snaplink/configX/foo"); got != nil {
		t.Errorf("expected nil for prefix-collision key, got %v", got)
	}
}

func TestParseKey_BarePrefixHasNoLeaf(t *testing.T) {
	if got := parseKey("/snaplink/config", "/snaplink/config"); got != nil {
		t.Errorf("expected nil for bare-prefix key, got %v", got)
	}
	if got := parseKey("/snaplink/config", "/snaplink/config/"); got != nil {
		t.Errorf("expected nil for bare-prefix-with-slash key, got %v", got)
	}
}

func TestParseKey_DropsEmptySegments(t *testing.T) {
	got := parseKey("/snaplink/config", "/snaplink/config//server//listen/")
	want := []string{"server", "listen"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKey = %v, want %v (empty segments dropped)", got, want)
	}
}

func TestBuildConfigMap_NestedKeys(t *testing.T) {
	got := buildConfigMap("/snaplink/config", []kv{
		{Key: "/snaplink/config/server/listen", Value: ":9090"},
		{Key: "/snaplink/config/logging/level", Value: "debug"},
	})
	server, ok := got["server"].(map[string]any)
	if !ok || server["listen"] != ":9090" {
		t.Errorf("server.listen = %v (server: %v)", server["listen"], got["server"])
	}
	logging, ok := got["logging"].(map[string]any)
	if !ok || logging["level"] != "debug" {
		t.Errorf("logging.level = %v", logging["level"])
	}
}

func TestBuildConfigMap_TypeCoercion(t *testing.T) {
	got := buildConfigMap("/snaplink/config", []kv{
		{Key: "/snaplink/config/bootstrap/disabled", Value: "true"},
		{Key: "/snaplink/config/audit/memory_capacity", Value: "512"},
	})
	boot := got["bootstrap"].(map[string]any)
	if boot["disabled"] != true {
		t.Errorf("disabled = %v (%T) want bool true", boot["disabled"], boot["disabled"])
	}
	audit := got["audit"].(map[string]any)
	switch audit["memory_capacity"].(type) {
	case int, int64, uint64, float64:
		// ok
	default:
		t.Errorf("memory_capacity = %v (%T) want numeric", audit["memory_capacity"], audit["memory_capacity"])
	}
}

func TestBuildConfigMap_YAMLValueParsedAsSubtree(t *testing.T) {
	// An operator who wants to drop a chunk of YAML at one etcd key
	// — common when seeding the whole config from a single put — gets
	// it parsed as a subtree, matching the env source semantics.
	got := buildConfigMap("/snaplink/config", []kv{
		{Key: "/snaplink/config/server", Value: "{listen: :9999, grpc_listen: :9090}"},
	})
	server, ok := got["server"].(map[string]any)
	if !ok {
		t.Fatalf("server = %v (%T) want map", got["server"], got["server"])
	}
	if server["listen"] != ":9999" || server["grpc_listen"] != ":9090" {
		t.Errorf("server subtree not parsed: %v", server)
	}
}

func TestBuildConfigMap_OffPrefixSkipped(t *testing.T) {
	got := buildConfigMap("/snaplink/config", []kv{
		{Key: "/other/garbage", Value: "ignored"},
		{Key: "/snaplink/config/server/listen", Value: ":9090"},
	})
	if _, ok := got["other"]; ok {
		t.Errorf("off-prefix key leaked: %v", got)
	}
	server := got["server"].(map[string]any)
	if server["listen"] != ":9090" {
		t.Errorf("server.listen = %v", server["listen"])
	}
}

func TestBuildConfigMap_EmptyReturnsNil(t *testing.T) {
	if got := buildConfigMap("/snaplink/config", nil); got != nil {
		t.Errorf("empty kvs should yield nil, got %v", got)
	}
	if got := buildConfigMap("/snaplink/config", []kv{
		{Key: "/other/x", Value: "y"},
	}); got != nil {
		t.Errorf("all-off-prefix should yield nil, got %v", got)
	}
}

func TestSource_Name(t *testing.T) {
	s := &Source{prefix: "/snaplink/config"}
	if got := s.Name(); got != "etcd:/snaplink/config" {
		t.Errorf("Name = %q", got)
	}
}

func TestNew_RequiresEndpoints(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected error when endpoints is empty")
	}
}

func TestNewWithClient_EmptyPrefixGetsDefault(t *testing.T) {
	// Passing a nil client is fine here — we only inspect the prefix
	// field that NewWithClient sets up. Dialing happens on Load, which
	// this test does not call.
	s := NewWithClient(nil, "")
	if s.prefix != DefaultPrefix {
		t.Errorf("prefix = %q, want default %q", s.prefix, DefaultPrefix)
	}
}

func TestNewWithClient_KeepsExplicitPrefix(t *testing.T) {
	s := NewWithClient(nil, "/custom")
	if s.prefix != "/custom" {
		t.Errorf("prefix = %q, want /custom", s.prefix)
	}
}
