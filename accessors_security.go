// Code generated. Server field accessors for security components.
package sso

import (
	"context"

	"github.com/snaplink/sso/security"
)

func (s *Server) JTIReplayStore() security.JTIReplayStore        { return s.jtiReplayStore }
func (s *Server) SubjectClientIndex() security.SubjectClientIndex { return s.subjectClientIndex }
func (s *Server) JARFetcher() security.JARFetcher                { return s.jarFetcher }
func (s *Server) JARDecrypter() security.JWEDecrypter            { return s.jarDecrypter }
func (s *Server) JWEResponseEncrypter() security.JWEEncrypter    { return s.jweResponseEncrypter }
func (s *Server) AccountLockout() security.AccountLockout        { return s.accountLockout }
func (s *Server) PairwiseStore() security.PairwiseSubjectStore   { return s.pairwiseStore }
func (s *Server) ClientCertExtractor() ClientCertExtractor       { return s.clientCertExtractor }
func (s *Server) DPoPNonceProvider() DPoPNonceProvider           { return s.dpopNonceProvider }

// EncryptIDTokenForClient encrypts an id_token for a specific client when
// the client has id_token_encrypted_response_alg configured.
func (s *Server) EncryptIDTokenForClient(ctx context.Context, client *Client, signed string) (string, bool) {
	return s.maybeEncryptIDToken(ctx, client, signed)
}
