package meteringhttp

const (
	PathUsageAppend       = "/api/v1/metering/usage"
	PathReservations      = "/api/v1/metering/reservations"
	PathReservationCommit = "/api/v1/metering/reservations/:reservation_id/commit"
	PathReservation       = "/api/v1/metering/reservations/:reservation_id"
	PathEntitlement       = "/api/v1/metering/entitlement"
)

const (
	ScopeMeteringWrite       = "metering:write"
	ScopeEntitlementRead     = "billing:entitlement:read"
	ErrorInsufficientScope   = "insufficient_scope"
	ErrorSourceUnauthorized  = "metering_source_unauthorized"
	ErrorDimensionNotAllowed = "metering_dimension_not_allowed"
	ErrorInvalidFact         = "metering_invalid_fact"
	ErrorInvalidReservation  = "metering_invalid_reservation"
	ErrorReservationNotFound = "metering_reservation_not_found"
	ErrorReservationConflict = "metering_reservation_conflict"
	ErrorIdempotencyConflict = "metering_idempotency_conflict"
	ErrorQuotaExceeded       = "metering_quota_exceeded"
	ErrorCounterOverflow     = "metering_counter_overflow"
	ErrorPeriodClosed        = "metering_period_closed"
	ErrorEntitlementMissing  = "metering_entitlement_missing"
	ErrorEntitlementNotFound = "metering_entitlement_not_found"
	ErrorRequestTooLarge     = "request_too_large"
	ErrorUnavailable         = "metering_unavailable"
)

const (
	headerAuthenticate  = "WWW-Authenticate"
	headerCacheControl  = "Cache-Control"
	headerPragma        = "Pragma"
	headerIdempotency   = "Idempotency-Key"
	cacheControlNoStore = "no-store"
	pragmaNoCache       = "no-cache"
	meteringRealm       = "metering"
	maxRequestBodyBytes = 64 << 10
	maxRequestIDLength  = 256
	maxIdempotencyBytes = 256
	maxTTLSeconds       = 24 * 60 * 60
)

const (
	responseFact        = "fact"
	responseCounter     = "counter"
	responseReservation = "reservation"
	responseEntitlement = "entitlement"
)
