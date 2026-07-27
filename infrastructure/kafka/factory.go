package kafkaaudit

import (
	"fmt"
	"os"
	"strings"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditsink"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// defaultCEFVendor / defaultCEFProduct mirror
// cmd/sso-server/serverbuildauthn's own CEF defaults (duplicated rather than
// imported: cmd/sso-server is the core module and this is a nested module —
// core never imports a nested module, so the constant travels by value, not
// by reference). Kept identical so an operator switching audit.kafka.format
// between "cef" and audit.cef (the file/stdout sink) sees the same header.
const (
	defaultCEFVendor  = "Snaplink"
	defaultCEFProduct = "SSO"
	// defaultSyslogFacility is RFC 5424's authpriv (10) — see
	// config.AuditSyslogConfig's doc for why facility 0 is never a
	// realistic operator choice for an application audit trail.
	defaultSyslogFacility = 10
	defaultSyslogAppName  = "sso-server"
)

// Factory adapts config.AuditKafkaConfig into New, selecting the wire
// Formatter from cfg.Format. The generated standard-kafka cold-profile
// registrar installs it through:
//
//	serverbuildauthn.RegisterAuditKafkaSinkFactory(kafkaaudit.Factory)
//
// See the package doc for the build command. It matches the
// AuditKafkaSinkFactory signature the composition registry expects.
func Factory(cfg config.AuditKafkaConfig, logger spi.Logger) (audit.Sink, error) {
	format, err := resolveFormat(cfg.Format)
	if err != nil {
		return nil, err
	}
	sink, err := New(Config{
		Brokers:      cfg.Brokers,
		Topic:        cfg.Topic,
		ClientID:     cfg.ClientID,
		RequiredAcks: cfg.RequiredAcks,
		BatchTimeout: cfg.BatchTimeout,
		Async:        cfg.Async,
	}, WithFormat(format))
	if err != nil {
		return nil, err
	}
	if logger != nil {
		logger.Info("audit: kafka sink constructed",
			"brokers", len(cfg.Brokers), "topic", cfg.Topic, "format", cfg.Format)
	}
	return sink, nil
}

// resolveFormat maps the config string onto an auditsink.Formatter. Empty
// (and "json") select FormatJSON; "cef"/"ocsf"/"syslog" reuse the SDK's
// existing SIEM formatters UNCHANGED over this transport.
func resolveFormat(name string) (auditsink.Formatter, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "json":
		return FormatJSON, nil
	case "cef":
		return auditsink.FormatCEF(defaultCEFVendor, defaultCEFProduct, ""), nil
	case "ocsf":
		return auditsink.FormatOCSF(), nil
	case "syslog":
		hostname, _ := os.Hostname()
		return auditsink.FormatSyslog(defaultSyslogFacility, hostname, defaultSyslogAppName, nil), nil
	default:
		return nil, fmt.Errorf("kafkaaudit: format %q must be json|cef|ocsf|syslog", name)
	}
}
