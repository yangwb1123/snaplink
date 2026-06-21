package sources

import (
	"context"
	"flag"
	"strings"

	"github.com/snaplink/sso/config/internal/parse"
)

// FlagSource lets CLI flags override config values. Operators don't
// type flag names like "--server.listen" (Go's stdlib flag package
// is fine with dots in names but the convention everywhere else is
// short hyphenated names), so the source uses an explicit Bind
// table mapping flag names → dotted config paths.
//
// Critically, ONLY flags the user actually set on the command line
// are emitted; unset flags don't override the file / env values
// underneath. This relies on flag.FlagSet.Visit, which walks set
// flags only.
//
// Construct via NewFlagSource(fs) then chain .Bind calls:
//
//	fs := flag.NewFlagSet("sso-server", flag.ExitOnError)
//	listen := fs.String("listen", "", "override server.listen")
//	level  := fs.String("log-level", "", "override logging.level")
//	fs.Parse(os.Args[1:])
//
//	flagSrc := config.NewFlagSource(fs).
//	    Bind("listen", "server.listen").
//	    Bind("log-level", "logging.level")
//
// FlagSource must be the LAST source in the Loader chain so it wins
// over file + env.
type FlagSource struct {
	flags    *flag.FlagSet
	bindings map[string]string // flag name → dotted config path
}

// NewFlagSource wraps the given FlagSet. The set must have been
// .Parse()'d before Load runs — FlagSource doesn't parse itself
// because the parent CLI controls argv lifecycle.
func NewFlagSource(fs *flag.FlagSet) *FlagSource {
	return &FlagSource{flags: fs, bindings: map[string]string{}}
}

// Bind maps a flag name to a dotted config path
// (e.g. "log-level" → "logging.level"). Returns the receiver for
// fluent chaining. Empty inputs are silently ignored — convenient
// when bindings are conditional on build tags / feature flags.
func (s *FlagSource) Bind(flagName, configPath string) *FlagSource {
	if flagName == "" || configPath == "" {
		return s
	}
	s.bindings[flagName] = configPath
	return s
}

// Name returns "flag".
func (s *FlagSource) Name() string {
	return "flag"
}

// Load emits one entry per *set* bound flag. Values are pushed
// through parse.Value so "true" / "42" become typed leaves the
// downstream YAML pass can land in bool / int fields.
func (s *FlagSource) Load(_ context.Context) (map[string]any, error) {
	if s.flags == nil || len(s.bindings) == 0 {
		return nil, nil
	}
	out := map[string]any{}
	s.flags.Visit(func(f *flag.Flag) {
		path, ok := s.bindings[f.Name]
		if !ok {
			return
		}
		parse.SetPath(out, strings.Split(path, "."), parse.Value(f.Value.String()))
	})
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
