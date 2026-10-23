package generate

import "testing"

func TestBatchContinuationR011A(t *testing.T) {
	scaffold := &Scaffold{}
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"unicode_initials", "éclair_δelta", "ÉclairΔelta"},
		{"repeated_underscores", "__camel___case__", "CamelCase"},
		{"repeated_hyphens", "--camel---case--", "CamelCase"},
		{"repeated_spaces", "  camel   case  ", "CamelCase"},
		{"mixed_delimiters", "_- camel_- -case _-", "CamelCase"},
	} {
		t.Run("camelize/"+tc.name, func(t *testing.T) {
			if got := scaffold.camelize(tc.input); got != tc.want {
				t.Errorf("camelize(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"single_segment_trailing_slash", "widget/", "widget"},
		{"nested_trailing_slash", "internal/widget/", "widget"},
		{"deep_path_trailing_slash", "root/middle/custom_widget/", "custom_widget"},
	} {
		t.Run("packageName/"+tc.name, func(t *testing.T) {
			if got := packageName(tc.input); got != tc.want {
				t.Errorf("packageName(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}
