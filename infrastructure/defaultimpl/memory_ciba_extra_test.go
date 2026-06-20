package defaultimpl_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oauth"
)

func TestMemoryCIBAStore_UpdateLastPoll(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryCIBAStore()
	id, err := s.Issue(ctx, sampleCIBA())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	stamp := time.Now().Add(time.Second).UTC().Truncate(time.Second)
	if err := s.UpdateLastPoll(ctx, id, stamp); err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}
	got, _ := s.Get(ctx, id)
	if !got.LastPoll.Equal(stamp) {
		t.Errorf("LastPoll = %v, want %v", got.LastPoll, stamp)
	}

	// UpdateLastPoll on an unknown id is a silent no-op (slow_down bookkeeping
	// must never fail the poll).
	if err := s.UpdateLastPoll(ctx, "unknown", stamp); err != nil {
		t.Errorf("UpdateLastPoll(unknown) = %v, want nil", err)
	}
}

func TestGenerateCIBAAuthReqID(t *testing.T) {
	a, err := defaultimpl.GenerateCIBAAuthReqID()
	if err != nil {
		t.Fatalf("GenerateCIBAAuthReqID: %v", err)
	}
	if !strings.HasPrefix(a, oauth.AuthReqIDPrefix) {
		t.Errorf("auth_req_id %q missing prefix %q", a, oauth.AuthReqIDPrefix)
	}
	b, _ := defaultimpl.GenerateCIBAAuthReqID()
	if a == b {
		t.Errorf("two auth_req_ids collided: %q", a)
	}
}
