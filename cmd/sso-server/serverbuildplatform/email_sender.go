package serverbuildplatform

import (
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/infrastructure/defaultimpl/emailsmtp"
	"github.com/snaplink/sso/shared/spi"
)

// BuildEmailSender resolves the built-in SMTP sender for the four
// shared/spi token-delivery senders (password reset, email verification,
// email change, org invitation). Disabled/no host preserves the previous
// byte-identical no-op-delivery behavior (nil, nil): cmd leaves the four SDK
// sender options unwired, same as before this existed.
//
// Translates config.SMTPConfig into emailsmtp.Config rather than passing the
// config type straight through: config/ is a composition-layer package
// (architecture_layer_test.go rank 6) and infrastructure/defaultimpl/emailsmtp
// is rank 4, so emailsmtp itself cannot import config (an upward edge the
// frozen, shrink-only layerExemptions list does not carry). This translation
// only happens here, at the cmd wiring site, which is allowed to import both.
func BuildEmailSender(cfg config.SMTPConfig, log spi.Logger) (*emailsmtp.Sender, error) {
	if !cfg.Enabled || cfg.Host == "" {
		return nil, nil
	}
	return emailsmtp.New(emailsmtp.Config{
		Enabled:      cfg.Enabled,
		Host:         cfg.Host,
		Port:         cfg.Port,
		Username:     cfg.Username,
		Password:     cfg.Password,
		From:         cfg.From,
		StartTLS:     cfg.StartTLS,
		Timeout:      cfg.Timeout,
		TemplatesDir: cfg.TemplatesDir,
		LinkBaseURL:  cfg.LinkBaseURL,
	}, log)
}
