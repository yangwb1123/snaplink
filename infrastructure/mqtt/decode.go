package mqttbus

import (
	"encoding/json"

	"github.com/snaplink/sso/platform/cluster"
)

// decodeEvent translates a received MQTT publish payload into a
// cluster.Event. Undecodable payloads are reported as not-ok so the
// caller skips them — mirrors etcd.go's decodeEvent (a garbage payload
// degrades the receiving replica to its TTL fallback, never a crash).
func decodeEvent(payload []byte) (cluster.Event, bool) {
	var evt cluster.Event
	if err := json.Unmarshal(payload, &evt); err != nil {
		return cluster.Event{}, false
	}
	return evt, true
}
