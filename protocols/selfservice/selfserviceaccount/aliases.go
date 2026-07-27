package selfserviceaccount

import "github.com/yangwb1123/snaplink/protocols/selfservice/selfservicecore"

// Deps is the self-service capability surface; it lives in selfservicecore so
// both this leaf and the selfservice facade can reference it without an import
// cycle. Aliased here so the moved handler bodies keep their unqualified Deps
// references.
type Deps = selfservicecore.Deps
