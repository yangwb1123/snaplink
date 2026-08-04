# Snaplink Stripe adapter Helm chart

This chart deploys the optional payment adapter as an active-active fleet. The
default three replicas share one PostgreSQL database and use fenced
`SKIP LOCKED` claims. HPA, PDB, zone/host spreading, HTTPS probes and a
read-only non-root runtime are enabled by default.

The chart deliberately does not create credentials or tenant bindings. Create:

- `bindings.existingConfigMap` with exactly the key in `bindings.key`; the key
  is mounted as one regular file through `subPath`, because the process rejects
  projected-volume symlinks and writable files;
- `secrets.existingSecret` with the PostgreSQL DSN, a mode-matched Stripe API
  key, one to sixteen `whsec_` webhook secrets, and every binding-referenced
  Billing client secret;
- `tls.existingSecret` with the configured certificate and private-key keys.

No production secret belongs in a values file. A minimal binding ConfigMap can
be created from the reviewed deployment artifact:

```sh
kubectl -n snaplink-sso create configmap snaplink-stripe-adapter-bindings \
  --from-file=bindings.json=ops/deploy/billing/stripe-adapter/bindings.json \
  --dry-run=client -o yaml | kubectl apply -f -
helm lint --strict ops/deploy/helm/snaplink-stripe-adapter
helm template stripe-adapter ops/deploy/helm/snaplink-stripe-adapter \
  --namespace snaplink-sso
```

For immutable delivery, set `image.digest` to `sha256:<64 lowercase hex>`; it
overrides the tag in the rendered reference. Set `externalRevision` to the
reviewed Secret/TLS/binding revision so external rotations trigger a rollout.
The runtime itself validates that `handlerTimeout >= 2*httpTimeout+1s`, claim
lease and shutdown drain ordering, API-key/test-live mode, account ownership,
and exact webhook API version.

`networkPolicy.enabled` is opt-in because DNS, PostgreSQL, SSO, Billing and
Stripe selectors/CIDRs are installation-specific. Enabling it with empty
ingress and egress arrays intentionally denies all traffic. Supply explicit
rules for the trusted public edge and probe source, DNS, PostgreSQL, SSO JWKS
and token endpoint, Billing, and `api.stripe.com` egress before enabling it.
