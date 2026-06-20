package releases_test

import (
	"errors"
	"testing"

	"github.com/snaplink/sso/platform/releases"
)

func validRelease(id string) *releases.Release {
	return &releases.Release{
		ID:            id,
		Channel:       releases.ChannelStable,
		Frontend:      releases.Artifact{GitRef: "v1.0.0", URI: "s3://buckets/fe.zip", SHA256: "abc"},
		Backend:       releases.Artifact{GitRef: "v1.0.0", URI: "ghcr.io/.../api:v1.0.0", Digest: "sha256:def"},
		SchemaVersion: 1,
	}
}

func TestValidate_Happy(t *testing.T) {
	if err := validRelease("rel-1").Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissingID(t *testing.T) {
	r := validRelease("")
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestValidate_RejectsOneSidedFrontend(t *testing.T) {
	r := validRelease("rel-1")
	r.Frontend = releases.Artifact{}
	if err := r.Validate(); !errors.Is(err, releases.ErrInvalidPair) {
		t.Fatalf("err = %v, want ErrInvalidPair", err)
	}
}

func TestValidate_RejectsOneSidedBackend(t *testing.T) {
	r := validRelease("rel-1")
	r.Backend = releases.Artifact{}
	if err := r.Validate(); !errors.Is(err, releases.ErrInvalidPair) {
		t.Fatalf("err = %v, want ErrInvalidPair", err)
	}
}
