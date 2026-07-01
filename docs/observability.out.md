I've read the file. This is the observability reference covering:

1. **Metrics** — 21 bounded-cardinality metrics (no per-path/per-user labels)
2. **Audit** — pipeline composition (`Async → Multi → Retry → leaf`), hard constraints (`SetMeta` only, W3C trace/span IDs), retention schedulers
3. **Tracing** — middleware ordering (probes outside ratelimit, tracing first inside)

Is there something specific you'd like to do with this file or related code? For example:
- Verify consistency against actual metric registrations in code
- Check that audit events use `SetMeta` everywhere
- Review retention scheduler implementations
- Add a new metric or audit event type
