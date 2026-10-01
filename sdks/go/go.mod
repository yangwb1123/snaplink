// The Go client SDK is its own module so it can be versioned and consumed
// independently of the server. It previously lived inside the root module,
// which meant its only version stream was the root vX.Y.Z tag - and a root tag
// also triggers the server release (binaries, archives, SBOMs, signatures and
// container images), so publishing the SDK would have published the server with
// no approval point in between.
//
// The package is stdlib-only and imports nothing from the rest of this
// repository, so the module boundary costs nothing technically. The module path
// is the repository path plus this directory because that is where Go can
// fetch it from: a subdirectory module must be addressed by its real path.
//
// Consequence worth knowing before releasing: Go requires a subdirectory
// module's version tag to be prefixed with the module path, so releases here are
// tagged `sdks/go/v<version>`, not the `sdk-<language>-v<version>` form the
// other SDK packages use. That prefix is required by the go command and cannot
// be shortened.
module github.com/yangwb1123/snaplink/sdks/go

go 1.26.1
