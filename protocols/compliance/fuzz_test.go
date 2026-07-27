package compliance

import (
	"testing"
	"time"
)

func FuzzBuildDataMap(f *testing.F) {
	seeds := []int64{0, 3600, 86400, -1}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sessionTTL int64) {
		opts := DataMapOptions{
			SessionTTL: time.Duration(sessionTTL) * time.Second,
		}
		dm := BuildDataMap(opts)
		if dm == nil {
			t.Error("expected non-nil DataMap")
		}
		_ = dm
	})
}
