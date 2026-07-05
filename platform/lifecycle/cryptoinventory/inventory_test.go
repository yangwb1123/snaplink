package cryptoinventory

import "testing"

func TestFilter_Match(t *testing.T) {
	entry := Entry{
		KeyID:     "kid-1",
		Algorithm: "EdDSA",
		Purpose:   PurposeSign,
		Status:    StatusActive,
	}

	tests := []struct {
		name string
		f    Filter
		want bool
	}{
		{"zero filter matches everything", Filter{}, true},
		{"status match", Filter{Status: StatusActive}, true},
		{"status mismatch", Filter{Status: StatusRetired}, false},
		{"purpose match", Filter{Purpose: PurposeSign}, true},
		{"purpose mismatch", Filter{Purpose: PurposeEncrypt}, false},
		{"algorithm match", Filter{Algorithm: "EdDSA"}, true},
		{"algorithm mismatch", Filter{Algorithm: "RS256"}, false},
		{"combined match", Filter{Status: StatusActive, Purpose: PurposeSign, Algorithm: "EdDSA"}, true},
		{"combined partial mismatch", Filter{Status: StatusActive, Purpose: PurposeEncrypt}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Match(entry); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}
