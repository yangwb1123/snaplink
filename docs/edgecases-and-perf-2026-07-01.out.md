This is an excellent and thorough analysis. I've read through all 5 directions and the priority summary. A few observations from the codebase architect's perspective:

**What stands out as most actionable:**

The **`TimeSource` interface** (①-1) is the highest-leverage item — it unlocks testability, clock-skew tolerance, and removes the monotonic-vs-wall-clock ambiguity in one pass. The existing `fix(security): use monotonic-clock-safe comparisons` commit shows the team already recognizes this; an interface just formalizes it.

**Cross-cutting note on ② + ④ (memory stores):** The JTI Bloom filter (②-1) and the shared `periodicReaper` (②-2) are actually the same problem — every memory store independently re-invents GC. A single `Reaper` goroutine that all stores register into would reduce code duplication AND let us add a `MaxEntries` backpressure signal centrally.

**On ③-1 (`authorization_details`):** The 06-30 analysis touched on RAR validation but missed unbounded size. This is a genuine DoS vector — an unvalidated `json.RawMessage` pass-through from HTTP body to JWT claim is the classic billion-laughs amplification path. Worth flagging as a P0 fix.

**One gap I'd add to the analysis:**

**`http.Request.Body` size in token introspection** — `POST /introspect` accepts `token` form param. If the token itself is a 1MB opaque string (not JWT), the server allocates 1MB on read before validation. A `MaxTokenBytes` check at the HTTP read boundary (before `bindOAuthParams`) would cut this off earlier than ⑤-1's JWT-level check.

Want me to:
1. **Verify any specific claims** against the actual code (grep for the patterns flagged)?
2. **Draft the Phase 0 implementation** (no code, just the structural approach)?
3. **Cross-reference against the existing ROADMAP v5.0 / 06-30 docs** for conflicts?
