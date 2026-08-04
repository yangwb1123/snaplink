package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	postgrescommerce "github.com/yangwb1123/snaplink/infrastructure/postgres/tenantcommerce"
	postgresledger "github.com/yangwb1123/snaplink/infrastructure/postgres/usageledger"
	commercehttp "github.com/yangwb1123/snaplink/interfaces/commerce"
	meteringhttp "github.com/yangwb1123/snaplink/interfaces/metering"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
)

type application struct {
	handler  http.Handler
	database *sql.DB
	jwks     *rs.JWKSCache
	audit    *auditModule
	quota    *quotaRelayRunner
	renewal  *renewalRunner
}

type applicationStores struct {
	commerce tenantcommerce.Store
	usage    ledger.Store
	bindings ledger.SourceBindingStore
	database *sql.DB
	checks   []readyCheck
}

type domainServices struct {
	commerce *tenantcommerce.Service
	usage    *ledger.Service
	sources  *ledger.SourceResolver
}

func buildApplication(config runtimeConfig) (*application, error) {
	stores, err := buildStores(config)
	if err != nil {
		return nil, err
	}
	upstream := newUpstreamHTTPClient(5 * time.Second)
	jwks := rs.NewJWKSCache(config.JWKSURL, remote.WithJWKSHTTPClient(upstream))
	cleanup := func() {
		jwks.Close()
		if stores.database != nil {
			_ = stores.database.Close()
		}
	}
	services, err := buildDomainServices(config, stores)
	if err != nil {
		cleanup()
		return nil, err
	}
	business := core.NewStdRouter()
	if err := mountBusinessAPIs(business, services, stores.commerce); err != nil {
		cleanup()
		return nil, err
	}
	auditModule, err := buildAuditModule(config, stores.commerce, stores.usage)
	if err != nil {
		cleanup()
		return nil, err
	}
	quotaRelay, err := buildQuotaRelay(config, stores.commerce, stores.commerce)
	if err != nil {
		if auditModule != nil {
			_ = auditModule.Close()
		}
		cleanup()
		return nil, err
	}
	metrics := newBillingMetrics(config.Renewals, time.Now)
	renewal := newRenewalRunner(config.Renewals, services.commerce, metrics.renewal)
	checks := applicationReadyChecks(config, stores.checks, upstream, auditModule, quotaRelay, renewal)
	handler := buildHTTPHandler(config, business, jwks, checks, metrics.handler())
	return &application{
		handler: handler, database: stores.database, jwks: jwks,
		audit: auditModule, quota: quotaRelay,
		renewal: renewal,
	}, nil
}

func applicationReadyChecks(
	config runtimeConfig, base []readyCheck, upstream *http.Client,
	auditModule *auditModule, quotaRelay *quotaRelayRunner, renewal *renewalRunner,
) []readyCheck {
	checks := append([]readyCheck{}, base...)
	checks = append(checks, readyCheck{name: "snaplink_jwks", check: jwksReadyCheck(config.JWKSURL, upstream)})
	if auditModule != nil {
		checks = append(checks, readyCheck{name: "audit_relay_module", check: auditModule.Ready})
	}
	if quotaRelay != nil {
		checks = append(checks, readyCheck{name: "tenant_quota_projection", check: quotaRelay.Ready})
	}
	if renewal != nil {
		checks = append(checks, readyCheck{name: "subscription_renewals", check: renewal.Ready})
	}
	return checks
}

func buildDomainServices(config runtimeConfig, stores applicationStores) (domainServices, error) {
	commerceService, err := tenantcommerce.NewService(stores.commerce)
	if err != nil {
		return domainServices{}, err
	}
	seedCtx, cancelSeed := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelSeed()
	if err := publishCatalog(seedCtx, config.CatalogFile, commerceService); err != nil {
		return domainServices{}, err
	}
	if err := applySourceBindings(seedCtx, config.SourceBindingsFile, stores.bindings); err != nil {
		return domainServices{}, err
	}
	usageService, err := ledger.NewService(stores.usage, stores.commerce, nil, nil)
	if err != nil {
		return domainServices{}, err
	}
	resolver, err := ledger.NewSourceResolver(stores.bindings)
	if err != nil {
		return domainServices{}, err
	}
	return domainServices{commerce: commerceService, usage: usageService, sources: resolver}, nil
}

func buildStores(config runtimeConfig) (applicationStores, error) {
	if config.DevMemory {
		commerceStore := tenantcommerce.NewMemoryStore()
		usageStore := ledger.NewMemoryStore()
		checks := []readyCheck{
			{name: "commerce_memory", check: func(context.Context) error { return nil }},
			{name: "usage_memory", check: func(context.Context) error { return nil }},
		}
		return applicationStores{
			commerce: commerceStore, usage: usageStore, bindings: usageStore, checks: checks,
		}, nil
	}
	database, err := postgresbackend.Open(postgresbackend.Config{
		DSN: config.Postgres.DSN, Dialect: postgresbackend.DialectPostgres,
		MaxOpenConns: config.Postgres.MaxOpen, MaxIdleConns: config.Postgres.MaxIdle,
		ConnMaxLifetime: config.Postgres.ConnMaxLifetime, ConnMaxIdleTime: config.Postgres.ConnMaxIdleTime,
	})
	if err != nil {
		return applicationStores{}, err
	}
	commerceStore, err := postgrescommerce.NewWithDB(database, postgresbackend.DialectPostgres)
	if err != nil {
		_ = database.Close()
		return applicationStores{}, err
	}
	usageStore, err := postgresledger.NewWithDB(database, postgresbackend.DialectPostgres)
	if err != nil {
		_ = database.Close()
		return applicationStores{}, err
	}
	checks := []readyCheck{
		{name: "commerce_postgres", check: commerceStore.Ping},
		{name: "usage_postgres", check: usageStore.Ping},
	}
	return applicationStores{
		commerce: commerceStore, usage: usageStore, bindings: usageStore,
		database: database, checks: checks,
	}, nil
}

func mountBusinessAPIs(
	router core.Router, services domainServices, commerceStore tenantcommerce.Store,
) error {
	if err := mountCommerceAPI(router, services.commerce, commerceStore, services.sources); err != nil {
		return err
	}
	_, err := meteringhttp.Mount(router, meteringhttp.Deps{
		Usage: services.usage, Entitlements: commerceStore, Sources: services.sources,
	})
	return err
}

func mountCommerceAPI(
	router core.Router, commands commercehttp.CommandService, queries commercehttp.QueryService,
	paymentSources commercehttp.PaymentSourceResolver,
) error {
	api, err := commercehttp.New(commercehttp.Deps{
		Commands: commands, Queries: queries, PaymentSources: paymentSources,
	})
	if err != nil {
		return err
	}
	adminRouter, err := newAdminContractRouter(router)
	if err != nil {
		return err
	}
	if err := api.RegisterRoutes(adminRouter); err != nil {
		return err
	}
	if err := adminRouter.ValidateComplete(); err != nil {
		return err
	}
	if err := api.RegisterPaymentEventRoute(router, commercehttp.ClientCredentialsScopeGate); err != nil {
		return err
	}
	if err := api.RegisterPaymentOrderReadRoute(router, commercehttp.ClientCredentialsScopeGate); err != nil {
		return err
	}
	return nil
}

func buildHTTPHandler(
	config runtimeConfig, business http.Handler, jwks *rs.JWKSCache, checks []readyCheck,
	metrics http.Handler,
) http.Handler {
	protected := rs.HTTPMiddleware(rs.Config{
		Issuer: config.Issuer, JWKSCache: jwks, ExpectedAud: config.Audience,
	}, business)
	mux := http.NewServeMux()
	registerHealthRoutes(mux, healthHandler{checks: checks, timeout: config.ReadyTimeout})
	mux.Handle(pathMetrics, metrics)
	mux.Handle("/", protected)
	return mux
}

func (app *application) Close() error {
	var result error
	if app.audit != nil {
		result = app.audit.Close()
	}
	if app.jwks != nil {
		app.jwks.Close()
	}
	if app.database != nil {
		if err := app.database.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("close PostgreSQL: %w", err))
		}
	}
	return result
}
