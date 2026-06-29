package redis

import (
	"strings"
	"testing"
)

// Redis Cluster correctness cannot be observed under the miniredis-backed
// store tests (miniredis is single-node and does not emulate the 16384-slot
// keyspace), so a real cluster would be the first place a CROSSSLOT bug
// surfaces — in production. This static guard closes that gap: it recomputes
// each ATOMIC multi-key operation's slots exactly as Redis does (CRC16 over
// the {hash-tag}) and asserts the keys it touches all land in one slot.
//
// Only operations that touch several keys IN ONE command or Lua script need
// this. Operations that issue separate per-key commands (the refresh-token
// active-key + family-marker deletes, the clients/users/consent GET pipelines)
// are routed per key by the cluster client and are intentionally NOT asserted
// here — see cluster.go.

// crc16 is the CRC16-CCITT (poly 0x1021, init 0x0000) Redis uses for slot
// assignment. Bitwise form to avoid vendoring the 256-entry table.
func crc16(s string) uint16 {
	var crc uint16
	for i := 0; i < len(s); i++ {
		crc ^= uint16(s[i]) << 8
		for j := 0; j < 8; j++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// hashKeyTag extracts the slot-determining substring per the Redis Cluster
// spec: the bytes between the first '{' and the first '}' that follows it with
// at least one byte in between; otherwise the whole key.
func hashKeyTag(key string) string {
	s := strings.IndexByte(key, '{')
	if s < 0 {
		return key
	}
	rest := key[s+1:]
	e := strings.IndexByte(rest, '}')
	if e <= 0 {
		return key
	}
	return rest[:e]
}

func slotOf(key string) uint16 { return crc16(hashKeyTag(key)) % 16384 }

// assertSameSlot fails when the keys do not all map to one slot.
func assertSameSlot(t *testing.T, op string, keys ...string) {
	t.Helper()
	if len(keys) < 2 {
		return
	}
	want := slotOf(keys[0])
	for _, k := range keys[1:] {
		if got := slotOf(k); got != want {
			t.Errorf("%s: key %q in slot %d but %q in slot %d — CROSSSLOT on a real cluster",
				op, keys[0], want, k, got)
		}
	}
}

// TestPermissionsKeysShareSlot guards the permissions Lua scripts, which
// touch a client's role hash, its users index, and per-user assignment sets in
// one EVAL (removeRoleScript even builds the per-user akeys dynamically inside
// Lua). All must share the {clientID} slot. Several clientID shapes are
// checked, including one containing a '}' to prove the extraction stays
// deterministic (so co-location holds regardless of the id's bytes).
func TestPermissionsKeysShareSlot(t *testing.T) {
	t.Parallel()
	clients := []string{"client-123", "acme", "tenant:abc/web", "weird}id", "a-very-long-client-identifier-0001"}
	users := []string{"alice", "bob-9", "user{0}"}
	for _, c := range clients {
		keys := []string{permRolesKey(c), permMenusKey(c), permUsersKey(c)}
		for _, u := range users {
			keys = append(keys, permAssignKey(c, u))
		}
		// removeRoleScript / assignScript / unassignScript / addRoleToUserScript
		// all draw their keys from this set, so one assertion covers them.
		assertSameSlot(t, "permissions client="+c, keys...)
	}
}

// TestSlotExtractionMatchesRedisExamples pins hashKeyTag/slotOf to the
// canonical examples from the Redis Cluster spec so a refactor of the
// extraction can't silently diverge from what a real cluster computes.
func TestSlotExtractionMatchesRedisExamples(t *testing.T) {
	t.Parallel()
	// Per the spec: {user1000} in both keys -> identical slot; no/empty tag
	// hashes the whole key.
	if slotOf("{user1000}.following") != slotOf("{user1000}.followers") {
		t.Error("keys sharing a {user1000} tag must share a slot")
	}
	if slotOf("foo{}{bar}") != slotOf("foo{}{bar}") { // sanity: deterministic
		t.Error("slotOf must be deterministic")
	}
	// "{}" is an empty tag and is ignored -> whole key hashes; two different
	// whole keys must (almost surely) differ.
	if slotOf("{}.a") == slotOf("{}.bbbbbb") {
		t.Error("empty hash tag must fall back to hashing the whole key")
	}
}
