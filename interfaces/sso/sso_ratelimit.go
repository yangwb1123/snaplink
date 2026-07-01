package sso

import "golang.org/x/time/rate"

// rateLimiterEntry pairs a token bucket limiter with the grant type it
// gates. Stored in grantRateLimiters by grant type URN.
type rateLimiterEntry struct {
	limiter *rate.Limiter
}
