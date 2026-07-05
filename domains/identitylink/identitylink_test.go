package identitylink

import "testing"

func TestGuardUnlink(t *testing.T) {
	tests := []struct {
		name           string
		activeCount    int
		hasOtherMethod bool
		wantErr        error
	}{
		{"only link, no password -> blocked", 1, false, ErrLastAuthMethod},
		{"only link, has password -> allowed", 1, true, nil},
		{"zero recorded (defensive), no password -> blocked", 0, false, ErrLastAuthMethod},
		{"two links, no password -> allowed", 2, false, nil},
		{"two links, has password -> allowed", 2, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := GuardUnlink(tt.activeCount, tt.hasOtherMethod)
			if err != tt.wantErr {
				t.Errorf("GuardUnlink(%d, %v) = %v, want %v", tt.activeCount, tt.hasOtherMethod, err, tt.wantErr)
			}
		})
	}
}
