package registry

import "testing"

func TestService_Endpoint(t *testing.T) {
	cases := []struct {
		name string
		s    Service
		want string
	}{
		{name: "host+port", s: Service{Address: "10.0.0.1", Port: 8080}, want: "10.0.0.1:8080"},
		{name: "zero port elides separator", s: Service{Address: "unix:/tmp/sock"}, want: "unix:/tmp/sock"},
		{name: "ipv4 + small port", s: Service{Address: "1.2.3.4", Port: 1}, want: "1.2.3.4:1"},
		{name: "ipv4 + large port", s: Service{Address: "1.2.3.4", Port: 65535}, want: "1.2.3.4:65535"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.s.Endpoint(); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{
		0:       "0",
		1:       "1",
		-1:      "-1",
		12345:   "12345",
		-12345:  "-12345",
		1 << 31: "2147483648",
	}
	for n, want := range cases {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestErrNotFound_StableMessage(t *testing.T) {
	// Wire-level contract: clients branch on this sentinel via errors.Is;
	// the message is also surfaced in some logs. Don't change it lightly.
	if ErrNotFound.Error() != "registry: service not found" {
		t.Errorf("ErrNotFound message changed: %q", ErrNotFound.Error())
	}
}

func TestEventType_Constants(t *testing.T) {
	// Wire-level enums consumed by Watch subscribers — keep stable.
	cases := map[EventType]string{
		EventAdded:   "added",
		EventRemoved: "removed",
		EventUpdated: "updated",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("EventType = %q, want %q", got, want)
		}
	}
}
