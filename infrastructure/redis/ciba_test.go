package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
)

func newCIBARequest(ttl time.Duration) *oauth.CIBARequest {
	now := time.Now()
	return &oauth.CIBARequest{
		ClientID:                "client-1",
		SubjectID:               "user-1",
		Provider:                "push",
		Scopes:                  []string{"openid", "profile", "email"},
		ACRValues:               "urn:mace:incommon:iap:silver",
		BindingMessage:          "Approve sign-in 42",
		Resources:               []string{"https://api.example.com"},
		Nonce:                   "n-0S6_WzA2Mj",
		ClientNotificationToken: "cnt-abc",
		RequestContext:          []byte(`{"extra":"ctx"}`),
		Status:                  oauth.CIBAPending,
		Interval:                oauth.DefaultCIBAPollInterval,
		CreatedAt:               now,
		ExpiresAt:               now.Add(ttl),
	}
}

// TestCIBAStore_UpdateLastPollPreservesConcurrentApproval is the regression
// guard for the silent-approval-loss bug: the device callback's SetStatus
// (atomic) and the client poll loop's UpdateLastPoll race on the SAME record.
// A non-atomic Get->mutate->Set in UpdateLastPoll can read the still-pending
// record, then write it back AFTER SetStatus flipped it to approved — reverting
// the approval so the grant never completes. The atomic single-key Lua mutates
// ONLY LastPoll and must therefore never clobber Status. Sequential ordering
// would NOT catch the bug (the old RMW's Get sees the approved status), so the
// writers run concurrently.
func TestCIBAStore_UpdateLastPollPreservesConcurrentApproval(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	id, err := s.Issue(ctx, newCIBARequest(time.Minute))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		for i := 0; i < 500; i++ {
			_ = s.UpdateLastPoll(ctx, id, time.Now())
		}
	}()
	// Approve mid-stream while the poll loop is hammering UpdateLastPoll.
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("SetStatus(approved): %v", err)
	}
	<-pollDone

	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != oauth.CIBAApproved {
		t.Fatalf("approval clobbered: status = %q, want approved", got.Status)
	}
	if got.LastPoll.IsZero() {
		t.Errorf("LastPoll was never recorded")
	}
}

// TestCIBAStore_IssueNormalizesEmptySlices guards the cjson-fidelity fix: a
// JSON client posting "resource":[] yields an empty-non-nil []string that
// json.Marshal would persist as "Resources":[]. The SetStatus/UpdateLastPoll
// Lua re-encode runs that through REAL Redis lua-cjson, which rewrites [] -> {}
// (object) and breaks the next Get's json.Unmarshal into []string — killing the
// request permanently. Issue must normalize empty slices to nil so the stored
// JSON is `null` (cjson-safe). Asserted on the RAW stored blob because miniredis
// encodes empty tables as [] (the OPPOSITE of real Redis), so a round-trip test
// would false-green; the stored-shape assertion catches a normalization regress.
func TestCIBAStore_IssueNormalizesEmptySlices(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	req := newCIBARequest(time.Minute)
	req.Resources = []string{} // empty-non-nil, as the JSON bind path produces
	req.Scopes = []string{}
	id, err := s.Issue(ctx, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	blob, err := rdb.Get(ctx, cibaKey(id)).Result()
	if err != nil {
		t.Fatalf("raw Get: %v", err)
	}
	if strings.Contains(blob, `"Resources":[]`) || strings.Contains(blob, `"Scopes":[]`) {
		t.Errorf("empty slice persisted as []; real-Redis cjson re-encode will corrupt it to {}: %s", blob)
	}
}

func TestCIBAStore_IssuePendingPoll(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	id, err := s.Issue(ctx, newCIBARequest(oauth.DefaultCIBARequestTTL))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(id, oauth.AuthReqIDPrefix) {
		t.Fatalf("auth_req_id missing namespace prefix: %q", id)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != oauth.CIBAPending {
		t.Fatalf("fresh request must be pending, got %q", got.Status)
	}
	if got.AuthReqID != id {
		t.Fatalf("AuthReqID not stamped: %q", got.AuthReqID)
	}
}

func TestCIBAStore_IssueRejectsMissingIdentity(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	bad := newCIBARequest(time.Minute)
	bad.SubjectID = ""
	if _, err := s.Issue(ctx, bad); !errors.Is(err, oauth.ErrCIBARequestInvalid) {
		t.Fatalf("Issue with empty subject must be ErrCIBARequestInvalid, got %v", err)
	}
	bad2 := newCIBARequest(time.Minute)
	bad2.ClientID = ""
	if _, err := s.Issue(ctx, bad2); !errors.Is(err, oauth.ErrCIBARequestInvalid) {
		t.Fatalf("Issue with empty client must be ErrCIBARequestInvalid, got %v", err)
	}
}

func TestCIBAStore_ApproveTransitionAndFidelity(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	req := newCIBARequest(oauth.DefaultCIBARequestTTL)
	id, err := s.Issue(ctx, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("SetStatus approve: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != oauth.CIBAApproved {
		t.Fatalf("status must be approved, got %q", got.Status)
	}

	// The status-flip must NOT mangle any other field: every captured
	// authorization parameter the eventual /token poll binds to issuance
	// must survive the atomic transition intact.
	if got.ClientID != req.ClientID || got.SubjectID != req.SubjectID ||
		got.Provider != req.Provider || got.ACRValues != req.ACRValues ||
		got.BindingMessage != req.BindingMessage || got.Nonce != req.Nonce ||
		got.ClientNotificationToken != req.ClientNotificationToken {
		t.Fatalf("scalar fields mangled by SetStatus: %+v", got)
	}
	if strings.Join(got.Scopes, " ") != strings.Join(req.Scopes, " ") {
		t.Fatalf("scopes mangled: %v", got.Scopes)
	}
	if strings.Join(got.Resources, " ") != strings.Join(req.Resources, " ") {
		t.Fatalf("resources mangled: %v", got.Resources)
	}
	if string(got.RequestContext) != string(req.RequestContext) {
		t.Fatalf("request_context mangled: %q", got.RequestContext)
	}
	if got.Interval != req.Interval {
		t.Fatalf("interval mangled: %v", got.Interval)
	}
}

func TestCIBAStore_DenyAndReResolutionGuard(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	id, err := s.Issue(ctx, newCIBARequest(time.Minute))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.SetStatus(ctx, id, oauth.CIBADenied); err != nil {
		t.Fatalf("SetStatus deny: %v", err)
	}
	// Same-status SetStatus is an idempotent no-op.
	if err := s.SetStatus(ctx, id, oauth.CIBADenied); err != nil {
		t.Fatalf("idempotent same-status SetStatus must succeed, got %v", err)
	}
	// A different transition on an already-resolved request is refused.
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); !errors.Is(err, oauth.ErrCIBARequestResolved) {
		t.Fatalf("re-resolution must be ErrCIBARequestResolved, got %v", err)
	}
}

func TestCIBAStore_SingleUseGrant(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	id, err := s.Issue(ctx, newCIBARequest(time.Minute))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	// Poll observes approved, mints tokens, then Deletes — single-use.
	if _, err := s.Get(ctx, id); err != nil {
		t.Fatalf("Get approved: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("redeemed request must be gone, got %v", err)
	}
	// Delete is idempotent.
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("second Delete must be no-op success, got %v", err)
	}
}

func TestCIBAStore_OracleLeak(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	// Unknown id collapses to not-found on Get and SetStatus.
	if _, err := s.Get(ctx, "ciba_ghost"); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("unknown Get must be ErrCIBARequestNotFound, got %v", err)
	}
	if err := s.SetStatus(ctx, "ciba_ghost", oauth.CIBAApproved); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("unknown SetStatus must be ErrCIBARequestNotFound, got %v", err)
	}

	// Expired id: same sentinel as unknown.
	id, err := s.Issue(ctx, newCIBARequest(30*time.Second))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mr.FastForward(31 * time.Second)
	if _, err := s.Get(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("expired Get must collapse to ErrCIBARequestNotFound, got %v", err)
	}
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("expired SetStatus must collapse to ErrCIBARequestNotFound, got %v", err)
	}
}

func TestCIBAStore_UpdateLastPollPreservesTTL(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	id, err := s.Issue(ctx, newCIBARequest(30*time.Second))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.UpdateLastPoll(ctx, id, time.Now()); err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LastPoll.IsZero() {
		t.Fatal("last_poll not persisted")
	}
	// KEEPTTL: the poll update must not extend the request lifetime.
	mr.FastForward(31 * time.Second)
	if _, err := s.Get(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("UpdateLastPoll must not extend TTL; want expired, got %v", err)
	}
	// UpdateLastPoll on an unknown id is a benign no-op.
	if err := s.UpdateLastPoll(ctx, "ciba_ghost", time.Now()); err != nil {
		t.Fatalf("UpdateLastPoll unknown must be no-op, got %v", err)
	}
}

func TestCIBAStore_Ping(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewCIBAStore(rdb)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping live: %v", err)
	}
	var nilStore *CIBAStore
	if err := nilStore.Ping(context.Background()); err == nil {
		t.Fatal("Ping on a nil store must error, not panic")
	}
}

// TestCIBAStore_ConsumeIfApproved verifies the atomic single-use claim: the Lua
// deletes+returns only an approved request; pending survives; a second consume
// is not-found. The returned blob is the original Go-marshaled bytes (not a
// cjson re-encode), so RFC 8707 resources round-trip intact.
func TestCIBAStore_ConsumeIfApproved(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)

	// Pending: not consumed; survives for the next poll.
	idPending, err := s.Issue(ctx, newCIBARequest(time.Minute))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.ConsumeIfApproved(ctx, idPending); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("pending should be not-found, got %v", err)
	}
	if _, err := s.Get(ctx, idPending); err != nil {
		t.Fatalf("pending request must survive a failed ConsumeIfApproved: %v", err)
	}

	// Approved: consumed once with resources intact; second consume not-found.
	id, err := s.Issue(ctx, newCIBARequest(time.Minute))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("SetStatus(approved): %v", err)
	}
	got, err := s.ConsumeIfApproved(ctx, id)
	if err != nil {
		t.Fatalf("consume approved: %v", err)
	}
	if got.SubjectID != "user-1" || got.Status != oauth.CIBAApproved {
		t.Fatalf("consumed record wrong: %+v", got)
	}
	if len(got.Resources) != 1 || got.Resources[0] != "https://api.example.com" {
		t.Fatalf("RFC 8707 Resources dropped/altered: %v", got.Resources)
	}
	if _, err := s.ConsumeIfApproved(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("second consume must be not-found (single-use), got %v", err)
	}
}

// TestCIBAStore_ConsumeIfApprovedAtomicRace asserts that of N concurrent polls
// of one approved request exactly ONE wins the indivisible server-side claim —
// the cross-replica invariant that stops one approval from minting N token sets.
func TestCIBAStore_ConsumeIfApprovedAtomicRace(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewCIBAStore(rdb)
	id, err := s.Issue(ctx, newCIBARequest(time.Minute))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("SetStatus(approved): %v", err)
	}
	const n = 16
	wins := make(chan bool, n)
	for range n {
		go func() {
			_, err := s.ConsumeIfApproved(ctx, id)
			wins <- err == nil
		}()
	}
	won := 0
	for range n {
		if <-wins {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("exactly one concurrent ConsumeIfApproved should win the single-use claim, got %d", won)
	}
}
