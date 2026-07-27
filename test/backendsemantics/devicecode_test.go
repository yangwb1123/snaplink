package backendsemantics

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

func issueDeviceCode(t *testing.T, store oauth.DeviceCodeStore, deviceCode, userCode string) {
	t.Helper()
	err := store.Issue(context.Background(), &oauth.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   "c-semantics",
		Scopes:     []string{"openid"},
		Interval:   5 * time.Second,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
}

// TestSemantics_Device_PendingNotConsumable: ConsumeIfApproved on a
// still-pending code fails with oauth.ErrDeviceCodeNotFound WITHOUT
// consuming — the device keeps polling the same code until the user acts.
// Identical on every backend.
func TestSemantics_Device_PendingNotConsumable(t *testing.T) {
	for _, b := range deviceCodeBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			issueDeviceCode(t, store, "dc-pending", "AAAA-1111")

			_, err := store.ConsumeIfApproved(context.Background(), "dc-pending")
			assertSentinel(t, err, oauth.ErrDeviceCodeNotFound)

			// The failed claim MUST NOT have consumed the pending code.
			got, err := store.GetByDeviceCode(context.Background(), "dc-pending")
			if err != nil {
				t.Fatalf("GetByDeviceCode after failed claim: %v", err)
			}
			if got.Approved {
				t.Fatalf("code unexpectedly approved: %+v", got)
			}
		})
	}
}

// TestSemantics_Device_ApprovedSingleWinner: after Approve, exactly one
// ConsumeIfApproved wins (returning the approving user); every later claim
// gets oauth.ErrDeviceCodeNotFound and the record is gone — the RFC 8628
// single-use guarantee, identical on every backend.
func TestSemantics_Device_ApprovedSingleWinner(t *testing.T) {
	for _, b := range deviceCodeBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			issueDeviceCode(t, store, "dc-approved", "BBBB-2222")

			if err := store.Approve(context.Background(), "BBBB-2222", "u-semantics", "password", nil); err != nil {
				t.Fatalf("Approve: %v", err)
			}

			got, err := store.ConsumeIfApproved(context.Background(), "dc-approved")
			if err != nil {
				t.Fatalf("winning claim: %v", err)
			}
			if got.UserID != "u-semantics" || !got.Approved {
				t.Fatalf("claimed code = %+v, want approved by u-semantics", got)
			}

			_, err = store.ConsumeIfApproved(context.Background(), "dc-approved")
			assertSentinel(t, err, oauth.ErrDeviceCodeNotFound)

			_, err = store.GetByDeviceCode(context.Background(), "dc-approved")
			assertSentinel(t, err, oauth.ErrDeviceCodeNotFound)
		})
	}
}

// TestSemantics_Device_UnknownLookups: unknown device_code and user_code
// lookups both collapse to oauth.ErrDeviceCodeNotFound on every backend.
func TestSemantics_Device_UnknownLookups(t *testing.T) {
	for _, b := range deviceCodeBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)

			_, err := store.GetByDeviceCode(context.Background(), "dc-never-issued")
			assertSentinel(t, err, oauth.ErrDeviceCodeNotFound)

			_, err = store.GetByUserCode(context.Background(), "ZZZZ-9999")
			assertSentinel(t, err, oauth.ErrDeviceCodeNotFound)
		})
	}
}
