package radiusauth

import (
	"context"
	"sync"
)

// fakeExchanger is an in-process stand-in for a RADIUS server exchange. It
// implements the Exchanger seam directly — NO real RADIUS server, NO mocking
// framework — the §2 "real impl, no mocks" discipline applied to the RADIUS
// boundary, mirroring ldap's fakeDirectory and kerberos's fake validator.
//
// It returns whatever verdict/attrs/err the test programs, and records the
// (username, password) pairs it received so a test can assert what was (or was
// NOT) sent — e.g. that an empty password never reaches the exchange.
type fakeExchanger struct {
	mu sync.Mutex

	// accept is the verdict returned when err is nil: true => Access-Accept,
	// false => clean Access-Reject.
	accept bool
	// attrs is the mapped reply-attribute map returned on an accept.
	attrs map[string]string
	// err, when set, is returned as the transport/operational failure (the
	// ErrServerUnavailable path) regardless of accept.
	err error

	// calls records every Exchange invocation, in order.
	calls []exchangeCall
}

type exchangeCall struct {
	username string
	password string
}

func (f *fakeExchanger) Exchange(_ context.Context, username, password string) (bool, map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, exchangeCall{username: username, password: password})
	if f.err != nil {
		return false, nil, f.err
	}
	return f.accept, f.attrs, nil
}

func (f *fakeExchanger) recorded() []exchangeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]exchangeCall(nil), f.calls...)
}

var _ Exchanger = (*fakeExchanger)(nil)
