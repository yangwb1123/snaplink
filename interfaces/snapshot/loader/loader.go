// Package loader resolves snapshot URI strings into a concrete
// snapshot.Storage backend + a name. Lives in its own package so the
// snapshot core package can stay free of upward dependencies on the
// storage backend implementations.
//
// Supported schemes today:
//
//   - file:///abs/path/to/snap-1.snap   → file backend rooted at the
//     parent dir, name = "snap-1" (extension stripped).
//   - file:///abs/dir/?name=snap-1      → explicit dir + name.
//   - inline:base64(<envelope-bytes>)   → in-memory backend with one
//     entry preloaded under name "inline".
//
// New schemes (s3://, http://) plug in here without changing callers.
package loader

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/snapshot/storagefile"
	"github.com/snaplink/sso/interfaces/snapshot/storageinline"
)

const (
	SchemeFile   = "file"
	SchemeInline = "inline"

	fileExt    = ".snap"
	inlineName = "inline"
)

// FromURI parses uri and returns a Storage that can serve the named
// entry. The Storage is freshly constructed on every call; the caller
// owns its lifetime.
func FromURI(uri string) (snapshot.Storage, string, error) {
	if uri == "" {
		return nil, "", errors.New("snapshot/loader: empty URI")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, "", fmt.Errorf("snapshot/loader: parse URI: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case SchemeFile:
		return fromFile(u)
	case SchemeInline:
		return fromInline(uri, u)
	default:
		return nil, "", fmt.Errorf("snapshot/loader: unsupported URI scheme %q (want file|inline)", u.Scheme)
	}
}

func fromFile(u *url.URL) (snapshot.Storage, string, error) {
	if u.Path == "" {
		return nil, "", errors.New("snapshot/loader: file URI requires a path")
	}
	dir := u.Path
	name := u.Query().Get("name")
	if name == "" {
		dir = filepath.Dir(u.Path)
		name = strings.TrimSuffix(filepath.Base(u.Path), fileExt)
	}
	if name == "" || name == "." || name == "/" {
		return nil, "", fmt.Errorf("snapshot/loader: cannot derive snapshot name from URI %q", u.String())
	}
	st, err := file.New(dir)
	if err != nil {
		return nil, "", fmt.Errorf("snapshot/loader: file backend: %w", err)
	}
	return st, name, nil
}

func fromInline(raw string, u *url.URL) (snapshot.Storage, string, error) {
	body := u.Opaque
	if body == "" {
		body = strings.TrimPrefix(raw, "inline:")
		body = strings.TrimPrefix(body, "//")
	}
	if body == "" {
		return nil, "", errors.New("snapshot/loader: inline URI requires base64 body after 'inline:'")
	}
	data, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		data, err = base64.RawURLEncoding.DecodeString(body)
	}
	if err != nil {
		return nil, "", fmt.Errorf("snapshot/loader: inline body not valid base64: %w", err)
	}
	st := inline.New()
	if err := st.Put(context.Background(), inlineName, data); err != nil {
		return nil, "", fmt.Errorf("snapshot/loader: seed inline storage: %w", err)
	}
	return st, inlineName, nil
}
