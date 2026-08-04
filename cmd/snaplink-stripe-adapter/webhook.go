package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type stripeEnvelope struct {
	ID         string  `json:"id"`
	Object     string  `json:"object"`
	Type       string  `json:"type"`
	Created    int64   `json:"created"`
	LiveMode   *bool   `json:"livemode"`
	Account    *string `json:"account"`
	APIVersion string  `json:"api_version"`
	Data       struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

type stripePaymentIntent struct {
	ID             string            `json:"id"`
	Object         string            `json:"object"`
	Amount         int64             `json:"amount"`
	AmountReceived int64             `json:"amount_received"`
	Currency       string            `json:"currency"`
	Metadata       map[string]string `json:"metadata"`
	LatestCharge   json.RawMessage   `json:"latest_charge"`
}

type stripeRefund struct {
	ID            string            `json:"id"`
	Object        string            `json:"object"`
	Amount        int64             `json:"amount"`
	Currency      string            `json:"currency"`
	PaymentIntent json.RawMessage   `json:"payment_intent"`
	Charge        json.RawMessage   `json:"charge"`
	Metadata      map[string]string `json:"metadata"`
	Status        string            `json:"status"`
}

type stripeDispute struct {
	ID            string            `json:"id"`
	Object        string            `json:"object"`
	Amount        int64             `json:"amount"`
	Currency      string            `json:"currency"`
	PaymentIntent json.RawMessage   `json:"payment_intent"`
	Charge        json.RawMessage   `json:"charge"`
	Metadata      map[string]string `json:"metadata"`
}

type stripeEventBinding struct {
	LiveMode   bool
	Account    string
	APIVersion string
}

func verifyStripeSignature(payload []byte, header string, secrets []string, now time.Time) error {
	timestamp, signatures, err := parseStripeSignature(header)
	if err != nil {
		return err
	}
	signed := append([]byte(strconv.FormatInt(timestamp, 10)+"."), payload...)
	matched := false
	for _, secret := range secrets {
		digest := hmac.New(sha256.New, []byte(secret))
		_, _ = digest.Write(signed)
		expected := digest.Sum(nil)
		for _, candidate := range signatures {
			if hmac.Equal(expected, candidate) {
				matched = true
			}
		}
	}
	if !matched || timestamp < now.Add(-webhookTolerance).Unix() || timestamp > now.Add(webhookTolerance).Unix() {
		return errInvalidSignature
	}
	return nil
}

func parseStripeSignature(header string) (int64, [][]byte, error) {
	if header == "" || len(header) > maxSignatureBytes {
		return 0, nil, errInvalidSignature
	}
	var timestamp int64
	timestampCount := 0
	var signatures [][]byte
	parts := strings.Split(header, ",")
	if len(parts) > 32 {
		return 0, nil, errInvalidSignature
	}
	for _, part := range parts {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return 0, nil, errInvalidSignature
		}
		switch key {
		case "t":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed <= 0 {
				return 0, nil, errInvalidSignature
			}
			timestamp, timestampCount = parsed, timestampCount+1
		case "v1":
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != sha256.Size || len(signatures) >= 16 {
				return 0, nil, errInvalidSignature
			}
			signatures = append(signatures, decoded)
		}
	}
	if timestampCount != 1 || len(signatures) == 0 {
		return 0, nil, errInvalidSignature
	}
	return timestamp, signatures, nil
}

func parseProviderFact(payload []byte, binding stripeEventBinding, now time.Time) (providerFact, error) {
	var envelope stripeEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Object != "event" ||
		!validStripeID(envelope.ID) || len(envelope.Data.Object) == 0 || !validEventBinding(envelope, binding) {
		return providerFact{}, errInvalidProviderFact
	}
	occurredAt := time.Unix(envelope.Created, 0).UTC()
	if envelope.Created <= 0 || occurredAt.After(now.Add(webhookTolerance)) {
		return providerFact{}, errInvalidProviderFact
	}
	base := providerFact{EventID: envelope.ID, EventType: envelope.Type, OccurredAt: occurredAt}
	var fact providerFact
	var err error
	switch envelope.Type {
	case stripeEventSucceeded:
		fact, err = parsePaymentIntentFact(base, envelope.Data.Object)
	case stripeEventFailed:
		return providerFact{}, errIgnoredEvent
	case stripeEventRefund, stripeEventRefundEdit:
		fact, err = parseRefundFact(base, envelope.Data.Object)
	case stripeEventWithdrawn, stripeEventReinstated:
		fact, err = parseDisputeFact(base, envelope.Data.Object)
	default:
		return providerFact{}, errUnsupportedEvent
	}
	if err != nil {
		return providerFact{}, err
	}
	if !validProviderFact(fact) {
		return providerFact{}, errInvalidProviderFact
	}
	return fact, nil
}

func validEventBinding(envelope stripeEnvelope, binding stripeEventBinding) bool {
	if envelope.LiveMode == nil || *envelope.LiveMode != binding.LiveMode || envelope.APIVersion != binding.APIVersion {
		return false
	}
	actualAccount := "platform"
	if envelope.Account != nil && *envelope.Account != "" {
		actualAccount = *envelope.Account
	}
	return actualAccount == binding.Account
}

func parsePaymentIntentFact(base providerFact, payload []byte) (providerFact, error) {
	var object stripePaymentIntent
	if err := json.Unmarshal(payload, &object); err != nil || object.Object != "payment_intent" ||
		!validStripeID(object.ID) || object.Amount <= 0 {
		return providerFact{}, errInvalidProviderFact
	}
	base.ProviderObjectID = object.ID
	base.PaymentIntentID = object.ID
	base.ChargeID = stripeExpandableID(object.LatestCharge)
	base.Currency = normalizeCurrency(object.Currency)
	base.ProviderAmountMinor = object.Amount
	base.MetadataTenantID, base.MetadataOrderID = metadataBinding(object.Metadata)
	if object.AmountReceived <= 0 || object.AmountReceived != object.Amount {
		return providerFact{}, errInvalidProviderFact
	}
	base.NormalizedType, base.NormalizedAmountMinor = eventCaptured, object.AmountReceived
	return base, nil
}

func parseRefundFact(base providerFact, payload []byte) (providerFact, error) {
	var object stripeRefund
	if err := json.Unmarshal(payload, &object); err != nil || object.Object != "refund" ||
		!validStripeID(object.ID) || object.Amount <= 0 {
		return providerFact{}, errInvalidProviderFact
	}
	if object.Status != "succeeded" {
		if validRefundStatus(object.Status) {
			return providerFact{}, errIgnoredEvent
		}
		return providerFact{}, errInvalidProviderFact
	}
	base.ProviderObjectID = object.ID
	base.PaymentIntentID = stripeExpandableID(object.PaymentIntent)
	base.ChargeID = stripeExpandableID(object.Charge)
	base.Currency, base.ProviderAmountMinor = normalizeCurrency(object.Currency), object.Amount
	base.NormalizedType, base.NormalizedAmountMinor = eventRefunded, object.Amount
	base.MetadataTenantID, base.MetadataOrderID = metadataBinding(object.Metadata)
	return base, nil
}

func validRefundStatus(status string) bool {
	switch status {
	case "pending", "requires_action", "failed", "canceled", "succeeded":
		return true
	default:
		return false
	}
}

func parseDisputeFact(base providerFact, payload []byte) (providerFact, error) {
	var object stripeDispute
	if err := json.Unmarshal(payload, &object); err != nil || object.Object != "dispute" ||
		!validStripeID(object.ID) || object.Amount <= 0 {
		return providerFact{}, errInvalidProviderFact
	}
	base.ProviderObjectID = object.ID
	base.PaymentIntentID = stripeExpandableID(object.PaymentIntent)
	base.ChargeID = stripeExpandableID(object.Charge)
	base.Currency, base.ProviderAmountMinor = normalizeCurrency(object.Currency), object.Amount
	base.NormalizedType, base.NormalizedAmountMinor = eventChargeback, object.Amount
	if base.EventType == stripeEventReinstated {
		base.NormalizedType = eventChargebackRev
	}
	base.MetadataTenantID, base.MetadataOrderID = metadataBinding(object.Metadata)
	return base, nil
}

func validProviderFact(fact providerFact) bool {
	if !validStripeID(fact.ProviderObjectID) || fact.Currency == "" || fact.ProviderAmountMinor <= 0 ||
		fact.EventID == "" || fact.NormalizedType == "" || fact.OccurredAt.IsZero() {
		return false
	}
	if fact.PaymentIntentID == "" && fact.ChargeID == "" && fact.MetadataOrderID == "" {
		return false
	}
	if (fact.MetadataTenantID == "") != (fact.MetadataOrderID == "") {
		return false
	}
	return fact.NormalizedAmountMinor > 0
}

func metadataBinding(metadata map[string]string) (string, string) {
	tenantID, orderID := metadata[metadataTenantID], metadata[metadataOrderID]
	if !validIdentity(tenantID) || !validIdentity(orderID) {
		return "", ""
	}
	return tenantID, orderID
}

func stripeExpandableID(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var direct string
	if json.Unmarshal(raw, &direct) == nil && validStripeID(direct) {
		return direct
	}
	var expanded struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &expanded) == nil && validStripeID(expanded.ID) {
		return expanded.ID
	}
	return ""
}

func normalizeCurrency(value string) string {
	if len(value) != 3 || value != strings.ToLower(value) {
		return ""
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			return ""
		}
	}
	return strings.ToUpper(value)
}

func validStripeID(value string) bool {
	return value != "" && len(value) <= 255 && value == strings.TrimSpace(value) &&
		!strings.ContainsAny(value, " /\\\r\n\t\x00")
}

func payloadDigest(payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return digest[:]
}

func signatureHeader(secret string, timestamp int64, payload []byte) string {
	message := append([]byte(fmt.Sprintf("%d.", timestamp)), payload...)
	digest := hmac.New(sha256.New, []byte(secret))
	_, _ = digest.Write(message)
	return fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(digest.Sum(nil)))
}
