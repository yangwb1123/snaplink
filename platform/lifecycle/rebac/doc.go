// Package rebac is a Zanzibar-style relationship-based access control (ReBAC)
// primitive: it stores relationship tuples of the form (object, relation,
// subject) — e.g. (document:42, viewer, user:alice) — and answers Check
// queries ("does subject have relation on object?") by walking those tuples.
//
// # Relationship to the other two authorization layers
//
// This is a THIRD, independent authorization model, additive alongside:
//
//   - domains/permissions: RBAC — a user holds named ROLES per client, each
//     role bundling PERMISSION codes ("user:read"). Coarse-grained,
//     app-scoped, good for "can this user use this feature at all".
//   - domains/conditionalaccess: attribute-based policy (ABAC-ish) — a
//     request's trust score/device posture/geo/time decides allow/deny/
//     step-up. Good for "is this REQUEST risky enough to challenge or block".
//   - rebac (this package): relationship-based — a SUBJECT's access to a
//     specific OBJECT INSTANCE is derived from a graph of who-relates-to-what
//     tuples, optionally through group membership. Good for "can alice view
//     THIS document" or "is bob an editor of THAT project", the fine-grained,
//     per-resource-instance question none of the other two models answer.
//
// None of the three consult each other. rebac has zero dependency on
// domains/permissions or domains/conditionalaccess, and neither of those
// packages depends on rebac. Hosts can consult [Engine.Check] from their own
// integration code (a custom HTTP handler, a gRPC interceptor, or a business
// logic layer). The SDK also exposes the opt-in FGA product routes: tuple
// management stays a normal cold route, while /authz/check is a fixed,
// lifecycle-managed business route when the standard router is in use. The
// separately gated GET /api/v1/admin/rebac/check remains operational debug
// only and is never a live authorization decision path.
//
// # Tuple model
//
// A [Tuple] is (Object, Relation, Subject). Object and, when the subject is a
// concrete principal rather than a userset reference, Subject are both
// "namespace:id" strings (e.g. "document:42", "user:alice") — the Zanzibar
// wire convention. Relation is a bare identifier ("viewer", "editor",
// "member") scoped to the object's namespace by convention (this package
// does not enforce a namespace-to-relation schema; see "Deferred" below).
//
// A tuple's Subject may itself be a USERSET REFERENCE — "namespace:id#relation"
// (e.g. "group:eng#member") — meaning "anyone who has `relation` on
// `namespace:id`", Zanzibar's userset-rewrite indirection. [SplitUserset]
// recognizes this shape.
//
// # Check semantics: direct tuples + ONE level of group indirection
//
// [Engine.Check](ctx, object, relation, subject) resolves to true when either:
//
//  1. A tuple (object, relation, subject) exists verbatim (direct grant), or
//  2. A tuple (object, relation, U) exists where U is a userset reference
//     "G#R", AND a tuple (G, R, subject) exists verbatim (subject is a
//     direct member of the referenced userset).
//
// Case 2 is expanded exactly ONE level: if a member tuple (G, R, subject)
// does not itself hold, but (G, R, W) holds for ANOTHER userset reference W,
// Check does NOT recurse into W. This bounds every Check call to at most two
// store reads (the direct lookup, plus one expansion per userset-typed
// subject found) with NO cycle detection needed — a tuple that references
// itself as its own userset can never cause unbounded recursion, because
// there is no recursion, by construction.
//
// # Explicitly scoped OUT (deferred)
//
// This is a deliberately solid SUBSET of full Zanzibar, not the whole spec:
//
//   - Full userset-rewrite rule DSL (union / intersection / exclusion /
//     tuple-to-userset "computed userset from a different relation on the
//     SAME object" rewrites, per the zanzibar paper §2.3 and the
//     OpenFGA/SpiceDB rewrite languages). Only the single "subject is a
//     userset reference, expand one level" indirection is implemented.
//   - Nested groups / multi-level indirection (group-of-groups). A userset
//     member that is ITSELF a userset reference is not expanded further.
//   - Wildcard subjects ("user:*" — "every user", SpiceDB/Zanzibar's public-
//     access marker). A wildcard subject is stored and compared as an
//     ordinary opaque string; Check never treats "*" specially, so a
//     wildcard tuple only matches a literal Check(..., subject="*") call,
//     never as an implicit match-anyone.
//   - Tuple-to-userset caching / any performance layer beyond the Memory
//     store's simple object+relation index. A production-scale backend
//     (SpiceDB-style) would add caching, revision snapshots, and consistency
//     tokens; this reference implementation recomputes on every Check.
//   - Expand / ListObjects / ListSubjects reverse-query APIs (Zanzibar's
//     other three RPCs). Only Check is implemented, per this package's scope.
//   - Namespace/relation config (Zanzibar's per-namespace rewrite schema
//     compiled from a config language). Object/Relation are free-form
//     strings here; nothing validates that "viewer" is a legal relation for
//     the "document" namespace.
//
// # Fail mode
//
// [Engine.Check] is fail-CLOSED on a store error or a nil/unwired store (both
// return an error, never a silent bool): unlike geo or risk-scoring signals,
// a ReBAC answer IS the authorization decision an integration is asking for,
// so an unanswerable Check must never be mistaken for an allow.
package rebac
