// Small string helpers shared by the Record* convenience functions.
// Split out of recorder_events.go to keep each file under the size
// budget; same package, so no call-site changes.

package audit

// maskTarget redacts the bulk of a phone number or email so the event
// remains auditable without storing the raw identifier.
func maskTarget(t string) string {
	if at := indexByte(t, '@'); at > 0 {
		// email: keep first char + domain
		if at == 1 {
			return t[:1] + "***" + t[at:]
		}
		return t[:1] + "***" + t[at-1:]
	}
	if len(t) > 4 {
		return t[:2] + repeat("*", len(t)-4) + t[len(t)-2:]
	}
	return "***"
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// itoa avoids importing strconv just for the tiny one-shot integer
// conversion in RecordRefreshTokenReuse.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func joinComma(s []string) string {
	if len(s) == 0 {
		return ""
	}
	n := len(s) - 1
	for _, e := range s {
		n += len(e)
	}
	b := make([]byte, 0, n)
	for i, e := range s {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, e...)
	}
	return string(b)
}
