package audit_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

// ocsfLine is a minimal local struct for asserting the OCSF required
// envelope fields without depending on the internal ocsfEvent type.
type ocsfLine struct {
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name"`
	CategoryUID  int    `json:"category_uid"`
	ClassUID     int    `json:"class_uid"`
	TypeUID      int    `json:"type_uid"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity"`
	StatusID     int    `json:"status_id"`
	Status       string `json:"status"`
	Time         int64  `json:"time"`
	Message      string `json:"message"`
	Metadata     struct {
		Version string `json:"version"`
		Product struct {
			Name       string `json:"name"`
			VendorName string `json:"vendor_name"`
		} `json:"product"`
		UID string `json:"uid"`
	} `json:"metadata"`
	Actor *struct {
		User struct {
			UID string `json:"uid"`
		} `json:"user"`
	} `json:"actor"`
	SrcEndpoint *struct {
		IP string `json:"ip"`
	} `json:"src_endpoint"`
	Unmapped map[string]string `json:"unmapped"`
}

func ocsfRecord(t *testing.T, e *audit.Event) ocsfLine {
	t.Helper()
	var buf strings.Builder
	sink := audit.NewOCSFSink(&buf)
	if err := sink.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	raw := strings.TrimRight(buf.String(), "\n")
	var out ocsfLine
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, raw)
	}
	return out
}

// TestOCSF_GoldenRepresentativeEvent covers a fully-populated event and
// asserts every OCSF-required envelope field plus the actor/src_endpoint
// optional objects.
func TestOCSF_GoldenRepresentativeEvent(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	out := ocsfRecord(t, &audit.Event{
		ID:        "evt-1",
		Type:      audit.EventLogin,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: ts,
		ActorID:   "alice",
		ActorIP:   "198.51.100.7",
		TenantID:  "acme",
	})

	if out.ActivityID != 1 || out.ActivityName != "Logon" {
		t.Errorf("activity = (%d, %q), want (1, Logon)", out.ActivityID, out.ActivityName)
	}
	if out.ClassUID != 3002 || out.CategoryUID != 3 {
		t.Errorf("class/category = (%d, %d), want (3002, 3)", out.ClassUID, out.CategoryUID)
	}
	if out.TypeUID != 3002*100+1 {
		t.Errorf("type_uid = %d, want %d", out.TypeUID, 3002*100+1)
	}
	if out.SeverityID != 1 || out.Severity != "Informational" {
		t.Errorf("severity = (%d, %q), want (1, Informational)", out.SeverityID, out.Severity)
	}
	if out.StatusID != 1 || out.Status != "Success" {
		t.Errorf("status = (%d, %q), want (1, Success)", out.StatusID, out.Status)
	}
	if out.Time != ts.UnixMilli() {
		t.Errorf("time = %d, want %d", out.Time, ts.UnixMilli())
	}
	if out.Metadata.Product.Name != "SSO" || out.Metadata.Product.VendorName != "Snaplink" {
		t.Errorf("product = %+v, want SSO/Snaplink", out.Metadata.Product)
	}
	if out.Metadata.UID != "evt-1" {
		t.Errorf("metadata.uid = %q, want evt-1", out.Metadata.UID)
	}
	if out.Actor == nil || out.Actor.User.UID != "alice" {
		t.Errorf("actor.user.uid = %+v, want alice", out.Actor)
	}
	if out.SrcEndpoint == nil || out.SrcEndpoint.IP != "198.51.100.7" {
		t.Errorf("src_endpoint.ip = %+v, want 198.51.100.7", out.SrcEndpoint)
	}
	if out.Unmapped["tenant_id"] != "acme" {
		t.Errorf("unmapped.tenant_id = %q, want acme", out.Unmapped["tenant_id"])
	}
}

// TestOCSF_EmptyFieldsOmitActorAndSrcEndpoint proves the optional actor/
// src_endpoint objects are omitted (nil) when ActorID/ActorIP are empty,
// and the failure outcome maps to status_id=2.
func TestOCSF_EmptyFieldsOmitActorAndSrcEndpoint(t *testing.T) {
	t.Parallel()
	out := ocsfRecord(t, &audit.Event{Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure})

	if out.Actor != nil {
		t.Errorf("actor = %+v, want nil (no ActorID)", out.Actor)
	}
	if out.SrcEndpoint != nil {
		t.Errorf("src_endpoint = %+v, want nil (no ActorIP)", out.SrcEndpoint)
	}
	if out.StatusID != 2 || out.Status != "Failure" {
		t.Errorf("status = (%d, %q), want (2, Failure)", out.StatusID, out.Status)
	}
	if len(out.Unmapped) != 0 {
		t.Errorf("unmapped = %v, want empty", out.Unmapped)
	}
}

// TestOCSF_UnknownEventTypeFallsBack exercises the generic/unmapped
// classification for a type outside the curated table.
func TestOCSF_UnknownEventTypeFallsBack(t *testing.T) {
	t.Parallel()
	out := ocsfRecord(t, &audit.Event{Type: audit.EventType("operator_custom_event"), Outcome: audit.OutcomeSuccess})

	if out.ClassUID == 0 {
		t.Error("class_uid must not be 0 for an unmapped type")
	}
	if out.ActivityName != "Other" {
		t.Errorf("activity_name = %q, want Other", out.ActivityName)
	}
}

// TestOCSF_MetadataFlattenedIntoUnmapped proves Metadata entries survive
// into the unmapped bag with a "meta." prefix so they can't collide with a
// named field, and that Message carries Reason.
func TestOCSF_MetadataFlattenedIntoUnmapped(t *testing.T) {
	t.Parallel()
	out := ocsfRecord(t, &audit.Event{
		Type:     audit.EventLogin,
		Outcome:  audit.OutcomeSuccess,
		Reason:   "step-up required",
		Metadata: map[string]string{"risk_score": "42"},
	})
	if out.Message != "step-up required" {
		t.Errorf("message = %q, want %q", out.Message, "step-up required")
	}
	if out.Unmapped["meta.risk_score"] != "42" {
		t.Errorf("unmapped[meta.risk_score] = %q, want 42", out.Unmapped["meta.risk_score"])
	}
}
