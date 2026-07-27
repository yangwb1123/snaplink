package rebac_test

import (
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/platform/lifecycle/rebac"
)

func TestSplitUserset(t *testing.T) {
	t.Parallel()
	cases := []struct {
		subject      string
		wantObject   string
		wantRelation string
		wantOK       bool
	}{
		{"group:eng#member", "group:eng", "member", true},
		{"user:alice", "", "", false},
		{"", "", "", false},
		{"group:eng#", "group:eng", "", true}, // Validate rejects this shape; SplitUserset is a pure syntactic split.
	}
	for _, c := range cases {
		obj, rel, ok := rebac.SplitUserset(c.subject)
		if obj != c.wantObject || rel != c.wantRelation || ok != c.wantOK {
			t.Errorf("SplitUserset(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.subject, obj, rel, ok, c.wantObject, c.wantRelation, c.wantOK)
		}
	}
}

func TestTupleValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		tuple   rebac.Tuple
		wantErr bool
	}{
		{"valid direct", rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "user:alice"}, false},
		{"valid userset subject", rebac.Tuple{Object: "document:42", Relation: "editor", Subject: "group:eng#member"}, false},
		{"empty object", rebac.Tuple{Object: "", Relation: "viewer", Subject: "user:alice"}, true},
		{"object no colon", rebac.Tuple{Object: "document42", Relation: "viewer", Subject: "user:alice"}, true},
		{"object empty namespace", rebac.Tuple{Object: ":42", Relation: "viewer", Subject: "user:alice"}, true},
		{"object empty id", rebac.Tuple{Object: "document:", Relation: "viewer", Subject: "user:alice"}, true},
		{"empty relation", rebac.Tuple{Object: "document:42", Relation: "", Subject: "user:alice"}, true},
		{"relation with colon", rebac.Tuple{Object: "document:42", Relation: "vie:wer", Subject: "user:alice"}, true},
		{"relation with hash", rebac.Tuple{Object: "document:42", Relation: "vie#wer", Subject: "user:alice"}, true},
		{"empty subject", rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: ""}, true},
		{"subject no colon", rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "alice"}, true},
		{"userset subject empty relation", rebac.Tuple{Object: "document:42", Relation: "editor", Subject: "group:eng#"}, true},
		{"userset subject bad object", rebac.Tuple{Object: "document:42", Relation: "editor", Subject: "groupeng#member"}, true},
	}
	for _, c := range cases {
		err := c.tuple.Validate()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: Validate() error = %v, wantErr %v", c.name, err, c.wantErr)
		}
		if err != nil && !errors.Is(err, rebac.ErrInvalidTuple) {
			t.Errorf("%s: Validate() error = %v, want ErrInvalidTuple", c.name, err)
		}
	}
}
