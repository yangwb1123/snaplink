package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// storageHealthResponse mirrors the JSON shape HandleStorageHealth emits so the
// test can assert the probe aggregation without re-deriving field tags.
type storageHealthResponse struct {
	Stores []struct {
		Name           string         `json:"name"`
		Reachable      bool           `json:"reachable"`
		PingLatencyMS  *float64       `json:"ping_latency_ms,omitempty"`
		SchemaVersions map[string]int `json:"schema_versions,omitempty"`
		Error          string         `json:"error,omitempty"`
	} `json:"stores"`
	GeneratedAt string `json:"generated_at"`
}

func decodeStorageHealth(t *testing.T, d *ServerDeps) storageHealthResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/storage-health", nil))
	HandleStorageHealth(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out storageHealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

// TestHandleStorageHealth_Aggregation covers the full probe matrix in one
// response: a nil-Ping source is reported reachable with no latency, a healthy
// pinging source reports latency + schema versions, a ping failure is reported
// unreachable with the error, and a schema-version error is surfaced while the
// store still counts as reachable. Output is sorted by name.
func TestHandleStorageHealth_Aggregation(t *testing.T) {
	t.Parallel()
	d := &ServerDeps{
		StorageHealthSources: func() []StorageHealthSource {
			return []StorageHealthSource{
				{
					// Out-of-order on purpose to prove name sorting.
					Name: "zeta-no-ping",
				},
				{
					Name: "alpha-healthy",
					Ping: func(context.Context) error { return nil },
					SchemaVersions: func(context.Context) (map[string]int, error) {
						return map[string]int{"sso": 3}, nil
					},
				},
				{
					Name: "beta-ping-fail",
					Ping: func(context.Context) error { return errors.New("dial tcp: connection refused") },
				},
				{
					Name: "gamma-schema-fail",
					Ping: func(context.Context) error { return nil },
					SchemaVersions: func(context.Context) (map[string]int, error) {
						return nil, errors.New("schema query failed")
					},
				},
			}
		},
	}

	resp := decodeStorageHealth(t, d)
	if len(resp.Stores) != 4 {
		t.Fatalf("got %d stores, want 4", len(resp.Stores))
	}
	if resp.GeneratedAt == "" {
		t.Fatal("generated_at must be set")
	}

	// Sorted ascending by name.
	wantOrder := []string{"alpha-healthy", "beta-ping-fail", "gamma-schema-fail", "zeta-no-ping"}
	for i, want := range wantOrder {
		if resp.Stores[i].Name != want {
			t.Fatalf("store[%d].Name = %q, want %q (sort broken)", i, resp.Stores[i].Name, want)
		}
	}

	byName := map[string]int{}
	for i, s := range resp.Stores {
		byName[s.Name] = i
	}

	healthy := resp.Stores[byName["alpha-healthy"]]
	if !healthy.Reachable {
		t.Fatal("alpha-healthy should be reachable")
	}
	if healthy.PingLatencyMS == nil {
		t.Fatal("healthy store must report ping latency")
	}
	if healthy.SchemaVersions["sso"] != 3 {
		t.Fatalf("schema version = %v, want sso=3", healthy.SchemaVersions)
	}

	pingFail := resp.Stores[byName["beta-ping-fail"]]
	if pingFail.Reachable {
		t.Fatal("beta-ping-fail must be unreachable")
	}
	if pingFail.Error == "" {
		t.Fatal("ping failure must surface its error")
	}
	if pingFail.PingLatencyMS == nil {
		t.Fatal("a ping that ran (even failing) reports its latency")
	}

	schemaFail := resp.Stores[byName["gamma-schema-fail"]]
	if !schemaFail.Reachable {
		t.Fatal("gamma-schema-fail pinged fine, so it is reachable despite schema error")
	}
	if schemaFail.Error == "" {
		t.Fatal("schema-version error must be surfaced")
	}
	if len(schemaFail.SchemaVersions) != 0 {
		t.Fatal("no schema versions should be present when the query errored")
	}

	noPing := resp.Stores[byName["zeta-no-ping"]]
	if !noPing.Reachable {
		t.Fatal("a nil-Ping source is reported reachable by definition")
	}
	if noPing.PingLatencyMS != nil {
		t.Fatal("a nil-Ping source must not report latency")
	}
}

// TestHandleStorageHealth_Empty covers the no-sources case: an empty store list
// still yields a well-formed 200 response.
func TestHandleStorageHealth_Empty(t *testing.T) {
	t.Parallel()
	d := &ServerDeps{
		StorageHealthSources: func() []StorageHealthSource { return nil },
	}
	resp := decodeStorageHealth(t, d)
	if len(resp.Stores) != 0 {
		t.Fatalf("expected no stores, got %d", len(resp.Stores))
	}
	if resp.GeneratedAt == "" {
		t.Fatal("generated_at must be set even with no stores")
	}
}
