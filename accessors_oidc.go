// Code generated. Server field accessors for OIDC, MFA, and anomaly components.
package sso

import (
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/spi"
)

func (s *Server) IDTokenIssuer() oidc.IDTokenIssuer              { return s.idTokenIssuer }
func (s *Server) MetadataSigner() oidc.MetadataSigner            { return s.metadataSigner }
func (s *Server) JARMSigner() oidc.JARMSigner                    { return s.jarmSigner }
func (s *Server) MFAProvider() spi.MFAProvider                   { return s.mfaProvider }
func (s *Server) MFAChallengeStore() spi.MFAChallengeStore       { return s.mfaChallengeStore }
func (s *Server) MFAChallengeTTL() time.Duration                 { return s.mfaChallengeTTL }
func (s *Server) AnomalyRunner() *anomaly.Runner                 { return s.anomalyRunner }
