# Host-native services

Install the statically linked binaries in `/usr/local/bin`, create locked
service accounts (`snaplink-sso`, `snaplink-billing`, and
`snaplink-stripe`, and `snaplink-audit-provisioner`), and install the unit files under
`/etc/systemd/system`. Copy the example environments to `/etc/snaplink`, replace
every placeholder, set ownership to the corresponding service account, and
mode `0600`. Install provisioner desired state mode `0644` or stricter at
`/etc/snaplink/audit-provisioner/desired-state.json`; install its separate OAuth
secret mode `0400` at
`/etc/snaplink/secrets/audit-provisioner-client-secret`. Both are owned by the
provisioner account.

Install the reviewed Stripe binding as
`/etc/snaplink/stripe-adapter/bindings.json`, owned by `snaplink-stripe`, mode
`0400` or `0440`. Run the same Stripe unit on both edge hosts with independent
environment files and the same binding revision. Each instance must remain on
`127.0.0.1:8091`; HAProxy provides TLS and local `/readyz` health routing.

The environment examples intentionally contain complete DSNs. Systemd does not
perform shell quoting inside `EnvironmentFile`; if a password contains spaces
or `%`, use a percent-encoded URI DSN or systemd credentials and render the
final variable during provisioning. Never put the secret in `ExecStart`.

Validate before enabling:

```sh
/usr/local/bin/sso-server --config /etc/snaplink/sso/config.yaml --validate-only
systemd-analyze verify /etc/systemd/system/sso-server.service
systemd-analyze verify /etc/systemd/system/snaplink-billing.service
systemd-analyze verify /etc/systemd/system/snaplink-stripe-adapter.service
systemd-analyze verify /etc/systemd/system/snaplink-audit-provisioner.service
systemctl enable --now sso-server snaplink-billing snaplink-stripe-adapter snaplink-audit-provisioner
curl --fail http://127.0.0.1:8080/readyz
curl --fail http://127.0.0.1:8090/readyz
curl --fail http://127.0.0.1:8091/readyz
curl --fail http://127.0.0.1:8092/readyz
```

On edge hosts, HAProxy owns public TLS and proxies Billing only through its
loopback backend. Do not relax `SNAPLINK_BILLING_LISTEN`. Use a distinct
`SNAPLINK_BILLING_{RELAY,QUOTA_RELAY,RENEWALS}_OWNER` on every host. The database leases
make multi-host workers safe; unique owners make incidents diagnosable.

The Stripe adapter generates an unguessable relay owner per process. Both edge
hosts share the dedicated `stripe_adapter` database; generation-fenced claims
and effect receipts make this active-active without a manually configured
leader. `TimeoutStopSec` covers both HTTP shutdown and worker drain. Do not
shorten it below twice `SNAPLINK_STRIPE_SHUTDOWN_DRAIN` plus operational
headroom.

Register the separate Billing quota client with exactly
`tenant-quota:projection:write` and resource `snaplink-sso-quota`; its secret
must not equal either the Audit Governance or payment-adapter secret. The SSO
config contains the matching `tenant-example` source record. Add one monotonic
record per production tenant before activating that tenant's subscription.

Run one provisioner per desired-state authority. SIGHUP forces an immediate
reload; periodic reconciliation remains active. A failed or stale revision
makes readiness fail without rolling back the last applied revision.
