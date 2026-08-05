package anomaly

// SignalType* are the wire-stable [Signal.Type] values. They are used as
// metric labels and as the branch keys in operator SIEM rules — renaming one
// silently breaks operator dashboards and alerting. Detector implementations
// (reference: infrastructure/defaultimpl/detectors) MUST alias these
// constants and MUST NOT emit raw string literals.
const (
	SignalTypeImpossibleTravel = "impossible_travel"
	SignalTypeVelocity         = "velocity_burst"
	SignalTypeNewDevice        = "new_device"
	SignalTypeNewCountry       = "new_country"
	SignalTypeBruteForceShadow = "brute_force_shadow"
)
