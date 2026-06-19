// Code generated. Server field accessors for OAuth grant stores and TTLs.
package sso

import (
	"time"

	"github.com/snaplink/sso/oauth"
)

func (s *Server) AuthCodeStore() oauth.AuthCodeStore             { return s.authCodeStore }
func (s *Server) AuthCodeTTL() time.Duration                     { return s.authCodeTTL }
func (s *Server) RefreshTokenStore() oauth.RefreshTokenStore     { return s.refreshTokenStore }
func (s *Server) RefreshTokenTTL() time.Duration                 { return s.refreshTokenTTL }
func (s *Server) DeviceCodeStore() oauth.DeviceCodeStore         { return s.deviceCodeStore }
func (s *Server) DeviceCodeTTL() time.Duration                   { return s.deviceCodeTTL }
func (s *Server) DeviceCodeInterval() time.Duration              { return s.deviceCodeInterval }
func (s *Server) DeviceVerifyBaseURL() string                    { return s.deviceVerifyBaseURL }
func (s *Server) PARStore() oauth.PARStore                       { return s.parStore }
func (s *Server) PARTTL() time.Duration                          { return s.parTTL }
func (s *Server) CIBAStore() oauth.CIBAStore                     { return s.cibaStore }
func (s *Server) CIBARequestTTL() time.Duration                  { return s.cibaRequestTTL }
func (s *Server) CIBAPollInterval() time.Duration                { return s.cibaPollInterval }
func (s *Server) DCRPolicy() *oauth.DCRPolicy                    { return s.dcrPolicy }
