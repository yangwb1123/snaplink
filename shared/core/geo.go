package core

// GeoInfo is one IP's geo lookup result. All fields are optional —
// backends may know the country but not the city, the city but not
// the timezone, etc. RecommendedLanguage is a BCP-47 tag (e.g.
// "en-US", "zh-CN", "de-DE"); empty when no mapping is known.
//
// It lives in core (the dependency-free leaf) rather than in geo so that
// low-level contracts — the spi.RiskScorer request and the anomaly
// LoginEvent — can carry geo data without importing the geo package. The
// geo package aliases this type (geo.GeoInfo), so every existing consumer
// is unaffected.
type GeoInfo struct {
	CountryCode         string `json:"country_code,omitempty"` // ISO 3166-1 alpha-2 ("US", "CN")
	Region              string `json:"region,omitempty"`       // ISO 3166-2 subdivision ("US-CA")
	City                string `json:"city,omitempty"`
	TimeZone            string `json:"time_zone,omitempty"`            // IANA tz database id
	RecommendedLanguage string `json:"recommended_language,omitempty"` // BCP-47

	// Latitude + Longitude in decimal degrees, populated when the
	// provider has lat/lon data (MaxMind GeoIP2 City, ipgeolocation.io,
	// most commercial DBs). Both zero = unknown; consumers MUST
	// NOT treat (0,0) as the Gulf of Guinea. Used by the
	// impossible-travel anomaly detector — provider impls without
	// lat/lon (`geo/static` shipped CIDR list) leave these zero
	// and the detector skips the distance check.
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
}
