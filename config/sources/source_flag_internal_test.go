package sources

import (
	"flag"
	"testing"
)

func TestFlagSource_EmptyBindIgnored(t *testing.T) {
	fs := newTestFlags([]string{"--listen=:9090"})
	src := NewFlagSource(fs).
		Bind("", "server.listen").
		Bind("listen", "")
	if len(src.bindings) != 0 {
		t.Errorf("empty Bind args should be no-ops, got %v", src.bindings)
	}
}

func newTestFlags(args []string) *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("listen", "", "")
	fs.String("log-level", "", "")
	fs.Bool("dev", false, "")
	_ = fs.Parse(args)
	return fs
}
