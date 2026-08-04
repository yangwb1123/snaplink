package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifyStripeSignatureRotationAndTolerance(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	payload := []byte(`{"id":"evt_test"}`)
	valid := signatureHeader("new-secret", now.Unix(), payload)
	second := strings.Split(signatureHeader("old-secret", now.Unix(), payload), ",")[1]
	tests := []struct {
		name    string
		body    []byte
		header  string
		wantErr bool
	}{
		{name: "rotated secret", body: payload, header: valid},
		{name: "multiple v1", body: payload, header: valid + "," + second},
		{name: "tampered body", body: append(payload, ' '), header: valid, wantErr: true},
		{name: "too old", body: payload, header: signatureHeader("new-secret", now.Add(-webhookTolerance-time.Second).Unix(), payload), wantErr: true},
		{name: "too far future", body: payload, header: signatureHeader("new-secret", now.Add(webhookTolerance+time.Second).Unix(), payload), wantErr: true},
		{name: "duplicate timestamp", body: payload, header: valid + ",t=" + stringInt(now.Unix()), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verifyStripeSignature(test.body, test.header, []string{"old-secret", "new-secret"}, now)
			if (err != nil) != test.wantErr {
				t.Fatalf("verifyStripeSignature() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestParseProviderFactSupportedEvents(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	tests := []struct {
		name, eventType string
		object          map[string]any
		wantType        string
		wantAmount      int64
		wantIntent      string
		wantCharge      string
	}{
		{name: "captured", eventType: stripeEventSucceeded, object: paymentIntentObject(1250, 1250), wantType: eventCaptured, wantAmount: 1250, wantIntent: "pi_one", wantCharge: "ch_one"},
		{name: "refund", eventType: stripeEventRefund, object: refundObject(), wantType: eventRefunded, wantAmount: 400, wantIntent: "pi_one", wantCharge: "ch_one"},
		{name: "refund updated", eventType: stripeEventRefundEdit, object: refundObject(), wantType: eventRefunded, wantAmount: 400, wantIntent: "pi_one", wantCharge: "ch_one"},
		{name: "chargeback", eventType: stripeEventWithdrawn, object: disputeObject(), wantType: eventChargeback, wantAmount: 700, wantIntent: "pi_one", wantCharge: "ch_one"},
		{name: "chargeback reversed", eventType: stripeEventReinstated, object: disputeObject(), wantType: eventChargebackRev, wantAmount: 700, wantIntent: "pi_one", wantCharge: "ch_one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fact, err := parseProviderFact(eventPayload(test.eventType, test.object, now), testEventBinding(), now)
			if err != nil {
				t.Fatalf("parseProviderFact() error = %v", err)
			}
			if fact.NormalizedType != test.wantType || fact.NormalizedAmountMinor != test.wantAmount ||
				fact.PaymentIntentID != test.wantIntent || fact.ChargeID != test.wantCharge || fact.Currency != "USD" {
				t.Fatalf("unexpected fact: %+v", fact)
			}
		})
	}
}

func TestParseProviderFactIgnoresNonFinancialPaymentFailure(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	payload := eventPayload(stripeEventFailed, paymentIntentObject(1250, 0), now)
	if _, err := parseProviderFact(payload, testEventBinding(), now); !errors.Is(err, errIgnoredEvent) {
		t.Fatalf("payment failure error = %v", err)
	}
}

func TestParseProviderFactRefundRequiresSucceededStatus(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	for _, eventType := range []string{stripeEventRefund, stripeEventRefundEdit} {
		for _, status := range []string{"pending", "requires_action", "failed", "canceled"} {
			t.Run(eventType+"/"+status, func(t *testing.T) {
				object := refundObject()
				object["status"] = status
				_, err := parseProviderFact(eventPayload(eventType, object, now), testEventBinding(), now)
				if !errors.Is(err, errIgnoredEvent) {
					t.Fatalf("status %q error = %v", status, err)
				}
			})
		}
	}
	object := refundObject()
	object["status"] = "mystery"
	if _, err := parseProviderFact(eventPayload(stripeEventRefund, object, now), testEventBinding(), now); !errors.Is(err, errInvalidProviderFact) {
		t.Fatalf("unknown refund status error = %v", err)
	}
}

func TestParseProviderFactEnforcesConfiguredStripeEventBinding(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	base := eventPayload(stripeEventSucceeded, paymentIntentObject(1250, 1250), now)
	tests := []struct {
		name    string
		payload []byte
		binding stripeEventBinding
	}{
		{name: "missing live mode", payload: deleteEventField(base, "livemode"), binding: testEventBinding()},
		{name: "live mode mismatch", payload: setEventField(base, "livemode", true), binding: testEventBinding()},
		{name: "api version mismatch", payload: base, binding: stripeEventBinding{Account: "platform", APIVersion: "2024-01-01"}},
		{name: "platform receives connected event", payload: setEventField(base, "account", "acct_other"), binding: testEventBinding()},
		{name: "connected account missing", payload: base, binding: stripeEventBinding{Account: "acct_expected", APIVersion: "2025-06-30.basil"}},
		{name: "connected account mismatch", payload: setEventField(base, "account", "acct_other"), binding: stripeEventBinding{Account: "acct_expected", APIVersion: "2025-06-30.basil"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseProviderFact(test.payload, test.binding, now); !errors.Is(err, errInvalidProviderFact) {
				t.Fatalf("binding error = %v", err)
			}
		})
	}
	connected := setEventField(base, "account", "acct_expected")
	binding := stripeEventBinding{Account: "acct_expected", APIVersion: "2025-06-30.basil"}
	if _, err := parseProviderFact(connected, binding, now); err != nil {
		t.Fatalf("matching connected account error = %v", err)
	}
}

func TestParseProviderFactRejectsUnsupportedAndMalformed(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	unsupported := eventPayload("customer.created", map[string]any{"id": "cus_one", "object": "customer"}, now)
	if _, err := parseProviderFact(unsupported, testEventBinding(), now); !errors.Is(err, errUnsupportedEvent) {
		t.Fatalf("unsupported error = %v", err)
	}
	invalidAmount := paymentIntentObject(1250, 1249)
	if _, err := parseProviderFact(eventPayload(stripeEventSucceeded, invalidAmount, now), testEventBinding(), now); !errors.Is(err, errInvalidProviderFact) {
		t.Fatalf("mismatched amount error = %v", err)
	}
	future := eventPayload(stripeEventRefund, refundObject(), now.Add(webhookTolerance+time.Second))
	if _, err := parseProviderFact(future, testEventBinding(), now); !errors.Is(err, errInvalidProviderFact) {
		t.Fatalf("future event error = %v", err)
	}
}

func paymentIntentObject(amount, received int64) map[string]any {
	return map[string]any{
		"id": "pi_one", "object": "payment_intent", "amount": amount,
		"amount_received": received, "currency": "usd", "latest_charge": map[string]any{"id": "ch_one"},
		"metadata": map[string]string{metadataTenantID: "tenant-one", metadataOrderID: "order-one"},
	}
}

func refundObject() map[string]any {
	return map[string]any{
		"id": "re_one", "object": "refund", "amount": 400, "currency": "usd",
		"payment_intent": "pi_one", "charge": "ch_one", "metadata": map[string]string{},
		"status": "succeeded",
	}
}

func disputeObject() map[string]any {
	return map[string]any{
		"id": "dp_one", "object": "dispute", "amount": 700, "currency": "usd",
		"payment_intent": map[string]any{"id": "pi_one"}, "charge": map[string]any{"id": "ch_one"},
		"metadata": map[string]string{},
	}
}

func eventPayload(eventType string, object map[string]any, created time.Time) []byte {
	payload, err := json.Marshal(map[string]any{
		"id": "evt_one", "object": "event", "type": eventType, "livemode": false,
		"api_version": "2025-06-30.basil",
		"created":     created.Unix(), "data": map[string]any{"object": object},
	})
	if err != nil {
		panic(err)
	}
	return payload
}

func setEventField(payload []byte, field string, value any) []byte {
	var event map[string]any
	if err := json.Unmarshal(payload, &event); err != nil {
		panic(err)
	}
	event[field] = value
	updated, err := json.Marshal(event)
	if err != nil {
		panic(err)
	}
	return updated
}

func deleteEventField(payload []byte, field string) []byte {
	var event map[string]any
	if err := json.Unmarshal(payload, &event); err != nil {
		panic(err)
	}
	delete(event, field)
	updated, err := json.Marshal(event)
	if err != nil {
		panic(err)
	}
	return updated
}

func testEventBinding() stripeEventBinding {
	return stripeEventBinding{Account: "platform", APIVersion: "2025-06-30.basil"}
}

func stringInt(value int64) string {
	payload, _ := json.Marshal(value)
	return string(payload)
}
