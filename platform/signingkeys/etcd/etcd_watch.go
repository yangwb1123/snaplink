package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/yangwb1123/snaplink/platform/signingkeys"
)

// List returns every currently live replica's announcement (the prefix
// snapshot), skipping any value that fails to decode rather than failing the
// whole call — one corrupt entry must not blind a replica to its peers.
func (r *Registry) List(ctx context.Context) ([]signingkeys.Announcement, error) {
	resp, err := r.client.Get(ctx, r.namespace(), clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("signingkeys/etcd: get: %w", err)
	}
	out := make([]signingkeys.Announcement, 0, resp.Count)
	for _, kv := range resp.Kvs {
		ann, ok := decodeAnnouncement(kv.Value)
		if !ok {
			continue
		}
		out = append(out, ann)
	}
	return out, nil
}

// Subscribe runs a prefix WATCH and emits one Event per change. A PUT becomes
// EventKeysUpserted carrying the decoded announcement; a DELETE (key removed
// or lease expired) becomes EventKeysRemoved carrying only the ReplicaID
// derived from the key path (a DELETE carries no value, and the Server's
// dropAllAdopted needs only the ReplicaID). The channel closes on ctx cancel,
// Close, or a fatal watch error.
func (r *Registry) Subscribe(ctx context.Context) (<-chan signingkeys.Event, error) {
	out := make(chan signingkeys.Event, 16)
	wch := r.client.Watch(ctx, r.namespace(), clientv3.WithPrefix())
	go func() {
		defer close(out)
		for resp := range wch {
			if err := resp.Err(); err != nil {
				return
			}
			for _, ev := range resp.Events {
				evt, ok := decodeWatchEvent(r.prefix, ev)
				if !ok {
					continue
				}
				select {
				case out <- evt:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// encodeAnnouncement JSON-marshals an announcement for the wire. Pure so it is
// unit-testable without etcd.
func encodeAnnouncement(ann signingkeys.Announcement) ([]byte, error) {
	return json.Marshal(ann)
}

// decodeAnnouncement JSON-unmarshals a wire value into an announcement,
// reporting ok=false for an undecodable value so callers skip it. Pure.
func decodeAnnouncement(value []byte) (signingkeys.Announcement, bool) {
	var ann signingkeys.Announcement
	if err := json.Unmarshal(value, &ann); err != nil {
		return signingkeys.Announcement{}, false
	}
	return ann, true
}

// replicaIDFromKey extracts the replica id from a full etcd key under prefix.
// The id is the path segment after "<prefix>/"; trimming the prefix and any
// leading slash and taking the base segment yields it. Pure.
func replicaIDFromKey(prefix, key string) string {
	trimmed := strings.TrimPrefix(key, prefix)
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed == "" {
		return ""
	}
	return path.Base(trimmed)
}

// decodeWatchEvent maps one etcd watch event to a signingkeys.Event. A PUT
// decodes to EventKeysUpserted (skipped if the value is garbage); a DELETE
// (key removed or lease expired) maps to EventKeysRemoved with the ReplicaID
// derived from the key path, since a DELETE carries no value. Any other event
// type, or a PUT with a nil/undecodable value, is reported not-ok so the
// caller skips it. Pure (no etcd I/O, no crypto) so it is unit-testable.
func decodeWatchEvent(prefix string, ev *clientv3.Event) (signingkeys.Event, bool) {
	if ev == nil || ev.Kv == nil {
		return signingkeys.Event{}, false
	}
	switch ev.Type {
	case mvccpb.PUT:
		ann, ok := decodeAnnouncement(ev.Kv.Value)
		if !ok {
			return signingkeys.Event{}, false
		}
		return signingkeys.Event{Type: signingkeys.EventKeysUpserted, Announcement: ann}, true
	case mvccpb.DELETE:
		replicaID := replicaIDFromKey(prefix, string(ev.Kv.Key))
		if replicaID == "" {
			return signingkeys.Event{}, false
		}
		return signingkeys.Event{
			Type:         signingkeys.EventKeysRemoved,
			Announcement: signingkeys.Announcement{ReplicaID: replicaID},
		}, true
	default:
		return signingkeys.Event{}, false
	}
}
