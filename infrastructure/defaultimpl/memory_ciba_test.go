package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oauth"
)

func sampleCIBA() *oauth.CIBARequest {
	now := time.Now().UTC()
	return &oauth.CIBARequest{
		ClientID:       "client-a",
		SubjectID:      "alice",
		Provider:       "ciba",
		Scopes:         []string{"openid", "profile"},
		ACRValues:      "urn:acr:strong",
		BindingMessage: "approve login 1234",
		Resources:      []string{"https://api.example"},
		Nonce:          "n-1",
		Interval:       5 * time.Second,
		CreatedAt:      now,
		ExpiresAt:      now.Add(2 * time.Minute),
	}
}

func TestMemoryCIBAStore_IssueGetRoundTrip(t *testing.T) {
	s := defaultimpl.NewMemoryCIBAStore()
	ctx := context.Background()
	id, err := s.Issue(ctx, sampleCIBA())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SubjectID != "alice" || got.ClientID != "client-a" || got.Status != oauth.CIBAPending {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if len(got.Scopes) != 2 || got.BindingMessage != "approve login 1234" || got.ACRValues != "urn:acr:strong" {
		t.Fatalf("field mismatch: %+v", got)
	}
}

func TestMemoryCIBAStore_IssueRejectsInvalid(t *testing.T) {
	s := defaultimpl.NewMemoryCIBAStore()
	ctx := context.Background()
	for _, r := range []*oauth.CIBARequest{nil, {ClientID: "c"}, {SubjectID: "u"}} {
		if _, err := s.Issue(ctx, r); !errors.Is(err, oauth.ErrCIBARequestInvalid) {
			t.Fatalf("want ErrCIBARequestInvalid, got %v", err)
		}
	}
}

func TestMemoryCIBAStore_MissingAndExpiredCollapse(t *testing.T) {
	s := defaultimpl.NewMemoryCIBAStore()
	ctx := context.Background()
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("unknown: want ErrCIBARequestNotFound, got %v", err)
	}
	r := sampleCIBA()
	r.ExpiresAt = time.Now().Add(-time.Second)
	id, _ := s.Issue(ctx, r)
	if _, err := s.Get(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("expired: want ErrCIBARequestNotFound, got %v", err)
	}
}

func TestMemoryCIBAStore_SetStatusLifecycle(t *testing.T) {
	s := defaultimpl.NewMemoryCIBAStore()
	ctx := context.Background()
	id, _ := s.Issue(ctx, sampleCIBA())
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// re-resolution refused
	if err := s.SetStatus(ctx, id, oauth.CIBADenied); !errors.Is(err, oauth.ErrCIBARequestResolved) {
		t.Fatalf("want ErrCIBARequestResolved, got %v", err)
	}
	// same-status idempotent
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("idempotent approve: %v", err)
	}
	got, _ := s.Get(ctx, id)
	if got.Status != oauth.CIBAApproved {
		t.Fatalf("status: %v", got.Status)
	}
}

func TestMemoryCIBAStore_DeleteIdempotent(t *testing.T) {
	s := defaultimpl.NewMemoryCIBAStore()
	ctx := context.Background()
	id, _ := s.Issue(ctx, sampleCIBA())
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
