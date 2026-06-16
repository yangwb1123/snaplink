package defaultimpl_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
)

func TestMemoryDeviceCodeStore_IssueGetApprove(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryDeviceCodeStore()

	dc := &oauth.DeviceCode{
		DeviceCode: "dc-1",
		UserCode:   "USER-CODE",
		ClientID:   "client-a",
		Scopes:     []string{"openid", "profile"},
		Nonce:      "n",
		Interval:   5,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	if err := s.Issue(ctx, dc); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	gotD, err := s.GetByDeviceCode(ctx, "dc-1")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if gotD.ClientID != "client-a" || len(gotD.Scopes) != 2 {
		t.Errorf("device code = %+v", gotD)
	}
	gotU, err := s.GetByUserCode(ctx, "USER-CODE")
	if err != nil {
		t.Fatalf("GetByUserCode: %v", err)
	}
	if gotU.DeviceCode != "dc-1" {
		t.Errorf("by-user-code = %+v", gotU)
	}

	if err := s.Approve(ctx, "USER-CODE", "user-7", "password", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	after, _ := s.GetByDeviceCode(ctx, "dc-1")
	if !after.Approved || after.UserID != "user-7" || after.Provider != "password" {
		t.Errorf("post-approve = %+v", after)
	}
	if after.Attributes["k"] != "v" {
		t.Errorf("attributes lost: %+v", after.Attributes)
	}
}

func TestMemoryDeviceCodeStore_Deny(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryDeviceCodeStore()
	_ = s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "dc", UserCode: "uc", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)})
	if err := s.Deny(ctx, "uc"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got, _ := s.GetByDeviceCode(ctx, "dc")
	if !got.Denied {
		t.Error("Denied flag not set")
	}
}

func TestMemoryDeviceCodeStore_NotFoundShapes(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryDeviceCodeStore()

	// nil / empty fields rejected.
	if err := s.Issue(ctx, nil); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("Issue(nil) = %v", err)
	}
	if err := s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "", UserCode: "u"}); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("Issue(no device code) = %v", err)
	}

	if _, err := s.GetByDeviceCode(ctx, "nope"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("GetByDeviceCode(unknown) = %v", err)
	}
	if _, err := s.GetByUserCode(ctx, "nope"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("GetByUserCode(unknown) = %v", err)
	}
	if err := s.Approve(ctx, "nope", "u", "p", nil); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("Approve(unknown) = %v", err)
	}
	if err := s.Deny(ctx, "nope"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("Deny(unknown) = %v", err)
	}
	if err := s.UpdateLastPoll(ctx, "nope", time.Now()); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("UpdateLastPoll(unknown) = %v", err)
	}
}

func TestMemoryDeviceCodeStore_UpdateLastPollAndDelete(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryDeviceCodeStore()
	_ = s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "dc", UserCode: "uc", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)})

	stamp := time.Now().Add(time.Second).Truncate(time.Second)
	if err := s.UpdateLastPoll(ctx, "dc", stamp); err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}
	got, _ := s.GetByDeviceCode(ctx, "dc")
	if !got.LastPoll.Equal(stamp) {
		t.Errorf("LastPoll = %v, want %v", got.LastPoll, stamp)
	}

	if err := s.Delete(ctx, "dc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetByDeviceCode(ctx, "dc"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("after delete by device code = %v", err)
	}
	if _, err := s.GetByUserCode(ctx, "uc"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("after delete by user code = %v", err)
	}
	// Idempotent delete.
	if err := s.Delete(ctx, "dc"); err != nil {
		t.Errorf("Delete(idempotent) = %v", err)
	}
}

func TestMemoryDeviceCodeStore_ExpiredCollapsesToNotFound(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryDeviceCodeStore()
	_ = s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "dc", UserCode: "uc", ClientID: "c", ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.GetByDeviceCode(ctx, "dc"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("expired GetByDeviceCode = %v", err)
	}
	if _, err := s.GetByUserCode(ctx, "uc"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("expired GetByUserCode = %v", err)
	}
	if err := s.Approve(ctx, "uc", "u", "p", nil); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("expired Approve = %v", err)
	}
	if err := s.Deny(ctx, "uc"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("expired Deny = %v", err)
	}
}

func TestGenerateDeviceAndUserCode(t *testing.T) {
	dc, err := defaultimpl.GenerateDeviceCode()
	if err != nil {
		t.Fatalf("GenerateDeviceCode: %v", err)
	}
	if len(dc) < 40 {
		t.Errorf("device code too short: %q", dc)
	}
	uc, err := defaultimpl.GenerateUserCode()
	if err != nil {
		t.Fatalf("GenerateUserCode: %v", err)
	}
	// Form XXXX-XXXX from the unambiguous alphabet.
	if len(uc) != 9 || uc[4] != '-' {
		t.Errorf("user code shape = %q, want XXXX-XXXX", uc)
	}
	if strings.ContainsAny(uc, "01OIL") {
		t.Errorf("user code contains ambiguous glyphs: %q", uc)
	}
	// Two mints should differ overwhelmingly.
	uc2, _ := defaultimpl.GenerateUserCode()
	if uc == uc2 {
		t.Errorf("two user codes collided: %q", uc)
	}
}
