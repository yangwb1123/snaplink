# Stripe adapter Kubernetes overlay

This overlay deploys the optional `snaplink-stripe-adapter` as three
active-active replicas. All replicas share PostgreSQL; durable claims use
`SKIP LOCKED`, expiring leases, and generation fencing. The public edge should
route Console checkout traffic to `/api/v1/checkout/sessions` and Stripe only to
`/webhooks/stripe`. Keep `/livez` and `/readyz` private to probes/operations.

Before applying:

1. Replace every example hostname, tenant/client id, return origin, Stripe
   account mode, and both independently pinned Stripe API versions in
   `settings.env` and `bindings.json`. `SNAPLINK_STRIPE_LIVE_MODE` has no
   application default and must stay explicit; its value must match the
   `sk_test_`/`rk_test_` or `sk_live_`/`rk_live_` credential class.
2. Create `snaplink-stripe-adapter-secrets` with keys `postgres-dsn`,
   `stripe-api-key`, `stripe-webhook-secrets`, and each binding's named Billing
   client secret (the example uses `tenant-acme-billing-client-secret`).
3. Create TLS secret `snaplink-stripe-adapter-tls` with `tls.crt` and `tls.key`.
4. In Snaplink register each checkout client for client credentials and grant
   only `billing:checkout:create` for adapter audience. Register each adapter
   Billing client with only `billing:payment:order:read billing:payment:write`
   for Billing audience/resource.
5. In Billing desired state bind that Billing client to the same tenant with
   source `payment:stripe`, enabled, revisioned, and no allowed dimensions.
6. Override `snaplink/stripe-adapter:prod` in the reviewed production overlay
   with an immutable `sha256:` digest; do not promote a mutable tag between
   environments.

Render and apply:

```sh
kubectl kustomize ops/deploy/billing/stripe-adapter
kubectl apply -k ops/deploy/billing/stripe-adapter
```

The Service preserves TLS to the adapter. Configure the ingress/controller for
TLS passthrough or HTTPS re-encryption and do not downgrade the Service hop to
HTTP. Restrict egress to DNS, PostgreSQL, Snaplink JWKS/token, Billing, and
`api.stripe.com`; restrict ingress to the public edge and kubelet/control-plane
probe sources. Concrete NetworkPolicy CIDRs/selectors are cluster-specific and
therefore intentionally not guessed here.

The binding ConfigMap key is mounted as one `subPath` file so the process sees a
regular, non-symlink desired-state file. It is cold startup configuration:
replace the ConfigMap and roll the Deployment to apply a binding revision; a
projected-volume symlink is intentionally rejected by the process.

`terminationGracePeriodSeconds` is greater than the documented worst-case HTTP
shutdown plus relay drain. Keep `SNAPLINK_STRIPE_SHUTDOWN_DRAIN` at least as long
as the claim lease, and keep `SNAPLINK_STRIPE_HANDLER_TIMEOUT` at least
`2*SNAPLINK_STRIPE_HTTP_TIMEOUT+1s`. During rolling updates, the disruption budget and topology
spreading retain quorum-like availability; relay delivery remains at least once.
See [`docs/stripe-payment-adapter.md`](../../../../docs/stripe-payment-adapter.md)
for signature rotation, scaling, incident response, and disaster recovery.
