package oauthvalidate

import (
	"testing"
	"testing/quick"
)

func TestIsValidResponseModeQuick(t *testing.T) {
	f := func(mode string) bool {
		knownValid := map[string]bool{
			"query": true, "fragment": true, "form_post": true,
		}
		result := IsValidResponseMode(mode)
		expected := knownValid[mode]
		return result == expected
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
