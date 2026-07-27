package defaultimpl

// The risk scorer and password-health checkers (rule-based risk, the no-op
// default, HIBP k-anonymity checker and the offline dictionary checker) live in
// the defaultrisk leaf so this directory stays within the per-directory
// file-count budget. defaultrisk depends only on shared/core + shared/spi.
// These aliases preserve the historical defaultimpl.* import surface unchanged.

import "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/defaultrisk"

type (
	DictionaryPasswordHealthChecker = defaultrisk.DictionaryPasswordHealthChecker
	DictionaryPasswordHealthConfig  = defaultrisk.DictionaryPasswordHealthConfig
	HIBPOption                      = defaultrisk.HIBPOption
	HIBPPasswordHealthChecker       = defaultrisk.HIBPPasswordHealthChecker
	NoopRiskScorer                  = defaultrisk.NoopRiskScorer
	RuleBasedRiskScorer             = defaultrisk.RuleBasedRiskScorer
	RuleBasedRiskScorerConfig       = defaultrisk.RuleBasedRiskScorerConfig
)

var (
	NewDictionaryPasswordHealthChecker = defaultrisk.NewDictionaryPasswordHealthChecker
	NewHIBPPasswordHealthChecker       = defaultrisk.NewHIBPPasswordHealthChecker
	NewRuleBasedRiskScorer             = defaultrisk.NewRuleBasedRiskScorer
	WithHIBPBaseURL                    = defaultrisk.WithHIBPBaseURL
	WithHIBPHTTPClient                 = defaultrisk.WithHIBPHTTPClient
	WithHIBPLogger                     = defaultrisk.WithHIBPLogger
	WithHIBPMinCount                   = defaultrisk.WithHIBPMinCount
	WithHIBPTimeout                    = defaultrisk.WithHIBPTimeout
	WithHIBPUserAgent                  = defaultrisk.WithHIBPUserAgent
)
