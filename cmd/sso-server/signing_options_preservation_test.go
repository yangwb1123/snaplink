package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestWireSigningIssuerPreservesEarlyReadinessOptions(t *testing.T) {
	var unavailable atomic.Bool
	var postgresCalls, redisCalls atomic.Int32
	b := &appBuilder{
		cfg: &config.Config{
			Server: config.ServerConfig{Issuer: "https://sso.example"},
			Keys:   config.KeysConfig{Signing: config.SigningConfig{Alg: "es256"}},
		},
		logger: quietLogger(),
		opts: []sso.Option{
			sso.WithReadyCheck("postgres", func(context.Context) error {
				postgresCalls.Add(1)
				if unavailable.Load() {
					return errors.New("fixture dependency unavailable")
				}
				return nil
			}),
			sso.WithReadyCheck("redis", func(context.Context) error {
				redisCalls.Add(1)
				return nil
			}),
		},
	}
	if err := b.wireSigningIssuer(); err != nil {
		t.Fatal(err)
	}
	srv := sso.NewServer(b.opts...)
	for _, phase := range []struct {
		name string
		down bool
		code int
	}{
		{"healthy", false, http.StatusOK},
		{"unavailable", true, http.StatusServiceUnavailable},
		{"restored", false, http.StatusOK},
	} {
		t.Run(phase.name, func(t *testing.T) {
			unavailable.Store(phase.down)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			checks := decodeReadyz(t, rec)
			if rec.Code != phase.code || checks["redis"] != "ok" {
				t.Fatalf("readiness=%d checks=%v; want status=%d and retained redis check", rec.Code, checks, phase.code)
			}
			value, present := checks["postgres"]
			if !present || (value == "ok") == phase.down {
				t.Fatalf("postgres readiness=%q present=%v; down=%v", value, present, phase.down)
			}
			live := httptest.NewRecorder()
			srv.Handler().ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/livez", nil))
			if live.Code != http.StatusOK {
				t.Fatalf("liveness=%d; dependency readiness must not change liveness", live.Code)
			}
		})
	}
	if postgresCalls.Load() < 3 || redisCalls.Load() < 3 {
		t.Fatal("pre-foundation dependency callbacks were not actually invoked")
	}
}
