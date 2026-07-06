package mqttbus

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/eclipse/paho.golang/paho"
)

// dialConnect opens a TCP (or TLS) connection to cfg.BrokerAddr and
// performs the MQTT CONNECT handshake, returning a ready-to-use client.
// clientID and cleanStart are parameters (not read from cfg) because
// Publish and Subscribe need DIFFERENT identities: two connections
// sharing one ClientID would have the broker disconnect the older one
// per the MQTT spec, so a persistent Subscribe session (cfg.ClientID,
// cleanStart=false) must never collide with a one-shot Publish
// connection (a derived, per-call-unique ID, cleanStart=true).
//
// The returned client has NO auto-reconnect and no OnClientError/
// OnServerDisconnect retry logic of its own — connection loss is
// reported solely via the returned Client's Done() channel, per
// doc.go's "Reconnection" section. Callers own calling Disconnect.
func dialConnect(ctx context.Context, cfg Config, clientID string, cleanStart bool) (*paho.Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	conn, err := dialConn(dialCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("mqttbus: dial %s: %w", cfg.BrokerAddr, err)
	}

	client := paho.NewClient(paho.ClientConfig{
		ClientID: clientID,
		Conn:     conn,
	})

	connectPacket := &paho.Connect{
		ClientID:   clientID,
		CleanStart: cleanStart,
		KeepAlive:  DefaultKeepAlive,
	}
	if cfg.Username != "" {
		connectPacket.UsernameFlag = true
		connectPacket.Username = cfg.Username
	}
	if cfg.Password != "" {
		connectPacket.PasswordFlag = true
		connectPacket.Password = []byte(cfg.Password)
	}
	if !cleanStart {
		sec := uint32(cfg.SessionExpiryInterval.Seconds())
		connectPacket.Properties = &paho.ConnectProperties{SessionExpiryInterval: &sec}
	}

	ca, err := client.Connect(dialCtx, connectPacket)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mqttbus: connect: %w", err)
	}
	if ca.ReasonCode != 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("mqttbus: connect refused: reason code %d", ca.ReasonCode)
	}
	return client, nil
}

// dialConn opens the raw transport (TLS when cfg.TLSConfig is set, plain
// TCP otherwise). Split out of dialConnect for the function-length budget.
func dialConn(ctx context.Context, cfg Config) (net.Conn, error) {
	if cfg.TLSConfig != nil {
		d := tls.Dialer{Config: cfg.TLSConfig}
		return d.DialContext(ctx, "tcp", cfg.BrokerAddr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", cfg.BrokerAddr)
}

// randomSuffix returns a short hex string for building a per-call-unique
// publisher ClientID (see dialConnect's doc for why Publish never reuses
// cfg.ClientID).
func randomSuffix() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
