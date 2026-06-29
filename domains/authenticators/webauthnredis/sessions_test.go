package redis

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators/webauthn"

	gw "github.com/go-webauthn/webauthn/webauthn"
	goredis "github.com/redis/go-redis/v9"
)

// fakeRedis is a tiny in-process [goredis.Cmdable] for tests. miniredis is the
// usual choice, but it is not a require entry in the parent module's go.mod
// (it reaches the build graph only transitively via the nested
// infrastructure/redis module), so importing it here would force a go.mod
// edit. Instead we embed the Cmdable interface — promoting every method we do
// not exercise — and override only the three the store touches (Set, GetDel,
// Ping). A settable clock emulates miniredis FastForward for TTL eviction.
type fakeRedis struct {
	goredis.Cmdable // unused methods; SessionStore never calls them
	data            map[string]fakeEntry
	now             time.Time
}

type fakeEntry struct {
	val     []byte
	expires time.Time // zero => no expiry
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{data: map[string]fakeEntry{}, now: time.Unix(1_700_000_000, 0)}
}

// advance moves the fake clock forward, emulating mr.FastForward so a key past
// its TTL is lazily evicted on the next read (mirrors Redis behavior).
func (f *fakeRedis) advance(d time.Duration) { f.now = f.now.Add(d) }

func (f *fakeRedis) live(key string) (fakeEntry, bool) {
	e, ok := f.data[key]
	if !ok {
		return fakeEntry{}, false
	}
	if !e.expires.IsZero() && !f.now.Before(e.expires) {
		delete(f.data, key)
		return fakeEntry{}, false
	}
	return e, true
}

func (f *fakeRedis) exists(key string) bool { _, ok := f.live(key); return ok }

func (f *fakeRedis) Ping(_ context.Context) *goredis.StatusCmd {
	return goredis.NewStatusResult("PONG", nil)
}

func (f *fakeRedis) Set(_ context.Context, key string, value any, ttl time.Duration) *goredis.StatusCmd {
	b, _ := value.([]byte)
	cp := append([]byte(nil), b...)
	var exp time.Time
	if ttl > 0 {
		exp = f.now.Add(ttl)
	}
	f.data[key] = fakeEntry{val: cp, expires: exp}
	return goredis.NewStatusResult("OK", nil)
}

func (f *fakeRedis) GetDel(_ context.Context, key string) *goredis.StringCmd {
	e, ok := f.live(key)
	if !ok {
		return goredis.NewStringResult("", goredis.Nil)
	}
	delete(f.data, key)
	return goredis.NewStringResult(string(e.val), nil)
}

func newStoreForTest(t *testing.T) (*SessionStore, *fakeRedis) {
	t.Helper()
	f := newFakeRedis()
	return NewSessionStore(f), f
}

func TestSessionStore_PutThenTake_RoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := newStoreForTest(t)
	ctx := context.Background()
	want := &gw.SessionData{
		Challenge:            "chal-xyz",
		RelyingPartyID:       "sso.example.com",
		UserID:               []byte("alice-handle"),
		AllowedCredentialIDs: [][]byte{[]byte("cred-1"), []byte("cred-2")},
	}

	if err := store.Put(ctx, "s1", want, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Take(ctx, "s1")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got.Challenge != want.Challenge {
		t.Errorf("Challenge: got %q want %q", got.Challenge, want.Challenge)
	}
	if got.RelyingPartyID != want.RelyingPartyID {
		t.Errorf("RelyingPartyID: got %q want %q", got.RelyingPartyID, want.RelyingPartyID)
	}
	if !bytes.Equal(got.UserID, want.UserID) {
		t.Errorf("UserID: got %x want %x", got.UserID, want.UserID)
	}
	if len(got.AllowedCredentialIDs) != len(want.AllowedCredentialIDs) {
		t.Fatalf("AllowedCredentialIDs len: got %d want %d", len(got.AllowedCredentialIDs), len(want.AllowedCredentialIDs))
	}
	for i := range want.AllowedCredentialIDs {
		if !bytes.Equal(got.AllowedCredentialIDs[i], want.AllowedCredentialIDs[i]) {
			t.Errorf("AllowedCredentialIDs[%d]: got %x want %x", i, got.AllowedCredentialIDs[i], want.AllowedCredentialIDs[i])
		}
	}
}

func TestSessionStore_TakeIsSingleUse(t *testing.T) {
	t.Parallel()
	store, _ := newStoreForTest(t)
	ctx := context.Background()

	if err := store.Put(ctx, "s1", &gw.SessionData{Challenge: "c"}, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := store.Take(ctx, "s1"); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	// GETDEL consumed the key; a replayed Finish* must miss.
	if _, err := store.Take(ctx, "s1"); !errors.Is(err, webauthn.ErrSessionUnknown) {
		t.Fatalf("second Take: got %v want ErrSessionUnknown", err)
	}
}

func TestSessionStore_TakeUnknown(t *testing.T) {
	t.Parallel()
	store, _ := newStoreForTest(t)
	if _, err := store.Take(context.Background(), "never-stored"); !errors.Is(err, webauthn.ErrSessionUnknown) {
		t.Fatalf("Take unknown: got %v want ErrSessionUnknown", err)
	}
}

func TestSessionStore_TTLExpiry(t *testing.T) {
	t.Parallel()
	store, f := newStoreForTest(t)
	ctx := context.Background()

	if err := store.Put(ctx, "s1", &gw.SessionData{Challenge: "c"}, 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// TTL eviction deletes the key outright, so an expired ceremony is gone and
	// indistinguishable from never-stored -> ErrSessionUnknown (Finish* fails).
	f.advance(31 * time.Second)
	if _, err := store.Take(ctx, "s1"); !errors.Is(err, webauthn.ErrSessionUnknown) {
		t.Fatalf("Take after expiry: got %v want ErrSessionUnknown", err)
	}
}

func TestSessionStore_PutNonPositiveTTLSkips(t *testing.T) {
	t.Parallel()
	store, f := newStoreForTest(t)
	ctx := context.Background()

	if err := store.Put(ctx, "s1", &gw.SessionData{Challenge: "c"}, 0); err != nil {
		t.Fatalf("Put ttl=0: %v", err)
	}
	if f.exists(sessKey("s1")) {
		t.Fatalf("ttl<=0 must not persist a never-expiring ceremony key")
	}
	if _, err := store.Take(ctx, "s1"); !errors.Is(err, webauthn.ErrSessionUnknown) {
		t.Fatalf("Take after skipped Put: got %v want ErrSessionUnknown", err)
	}
}

func TestSessionStore_Ping(t *testing.T) {
	t.Parallel()
	store, _ := newStoreForTest(t)
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	// Nil-safe: an unconfigured store reports an error rather than panicking.
	var nilStore *SessionStore
	if err := nilStore.Ping(context.Background()); err == nil {
		t.Fatalf("nil store Ping: want error, got nil")
	}
}
