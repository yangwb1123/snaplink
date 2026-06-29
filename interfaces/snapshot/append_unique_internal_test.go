package snapshot

import (
	"reflect"
	"testing"
)

func TestAppendUnique(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		dst  []string
		add  string
		want []string
	}{
		{name: "empty dst", dst: nil, add: "a", want: []string{"a"}},
		{name: "no overlap", dst: []string{"a"}, add: "b", want: []string{"a", "b"}},
		{name: "already present", dst: []string{"a", "b"}, add: "b", want: []string{"a", "b"}},
		{name: "exact match", dst: []string{"x"}, add: "x", want: []string{"x"}},
		{name: "case sensitive", dst: []string{"A"}, add: "a", want: []string{"A", "a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appendUnique(tc.dst, tc.add)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
