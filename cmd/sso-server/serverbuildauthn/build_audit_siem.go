package serverbuildauthn

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/buildinfo"
	"github.com/snaplink/sso/shared/spi"
)

const (
	// defaultCEFVendor / defaultCEFProduct back AuditCEFConfig.Vendor/
	// Product when the operator leaves them blank — the SIEM-formats task's
	// controller-adjudicated default.
	defaultCEFVendor  = "Snaplink"
	defaultCEFProduct = "SSO"

	// defaultSyslogFacility is RFC 5424's authpriv (10). Facility 0
	// (kernel) is never a realistic operator choice for an application
	// audit trail, so treating the config zero-value as "unset" here is
	// safe — same convention AuditWebhookRetryConfig already uses.
	defaultSyslogFacility = 10
	defaultSyslogAppName  = "sso-server"
)

// resolveAuditSinkOutput opens the writer target named by output: "stdout",
// "stderr", or a file path (opened append-only, created 0600 — formatted
// audit output can still carry truncated IPs / hashed actor ids even after
// PII redaction, so it gets the same restrictive mode as other
// credential-adjacent files). A file target stays open for the process
// lifetime — matching this SDK's other simple long-lived log targets — and
// is deliberately NOT registered for graceful Close, same as the OS
// reclaiming stdout/stderr on exit.
func resolveAuditSinkOutput(output string) (io.Writer, error) {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	case "":
		return nil, errors.New("output is required (stdout, stderr, or a file path)")
	default:
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", output, err)
		}
		return f, nil
	}
}

// buildFormatterSink is the ONE construction step shared by the CEF, OCSF,
// and syslog builders below — resolve the output target, then hand it to
// ctor — so enabling any subset of the three independent audit.cef/
// audit.ocsf/audit.syslog config blocks doesn't triplicate
// output-resolution code.
func buildFormatterSink(output string, ctor func(io.Writer) audit.Sink) (audit.Sink, error) {
	w, err := resolveAuditSinkOutput(output)
	if err != nil {
		return nil, err
	}
	return ctor(w), nil
}

// firstNonEmpty returns the first non-empty value, or "" if all are empty.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// buildAuditCEFSink resolves vendor/product/version defaults (Snaplink/SSO/
// the running binary's build version) and wires audit.NewCEFSink.
func buildAuditCEFSink(cfg config.AuditCEFConfig) (audit.Sink, error) {
	vendor := firstNonEmpty(cfg.Vendor, defaultCEFVendor)
	product := firstNonEmpty(cfg.Product, defaultCEFProduct)
	version := cfg.Version
	if version == "" {
		version, _, _ = buildinfo.Resolve("")
	}
	return buildFormatterSink(cfg.Output, func(w io.Writer) audit.Sink {
		return audit.NewCEFSink(w, vendor, product, version)
	})
}

func buildAuditOCSFSink(cfg config.AuditOCSFConfig) (audit.Sink, error) {
	return buildFormatterSink(cfg.Output, func(w io.Writer) audit.Sink {
		return audit.NewOCSFSink(w)
	})
}

// buildAuditSyslogSink resolves hostname (os.Hostname() when unset) and
// facility (authpriv when unset) and wires audit.NewSyslogSink with the
// default JSON inner formatter (config exposes no CEF-over-syslog knob
// today — that composition is available programmatically via FormatSyslog
// for a future roadmap item, not config-driven yet).
func buildAuditSyslogSink(cfg config.AuditSyslogConfig) (audit.Sink, error) {
	hostname := cfg.Hostname
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}
	facility := cfg.Facility
	if facility == 0 {
		facility = defaultSyslogFacility
	}
	appName := firstNonEmpty(cfg.AppName, defaultSyslogAppName)
	return buildFormatterSink(cfg.Output, func(w io.Writer) audit.Sink {
		return audit.NewSyslogSink(w, facility, hostname, appName, nil)
	})
}

// BuildAuditSIEMSinks compiles every enabled CEF/OCSF/syslog formatter sink
// from cfg, ready to fan into the primary MultiSink alongside the webhook
// subscriptions. Each is a bare WriterSink over its output target — no
// RetryingSink: these are local/stdout/file targets, not network
// deliveries (network SIEM transport is a later roadmap item that reuses
// these exact formatters unchanged). Returns a nil slice (not an error)
// when none of the three independent blocks are enabled.
func BuildAuditSIEMSinks(cfg config.AuditConfig, logger spi.Logger) ([]audit.Sink, error) {
	var sinks []audit.Sink
	if cfg.CEF.Enabled {
		sink, err := buildAuditCEFSink(cfg.CEF)
		if err != nil {
			return nil, fmt.Errorf("audit.cef: %w", err)
		}
		sinks = append(sinks, sink)
		logger.Info("audit: cef sink enabled", "output", cfg.CEF.Output)
	}
	if cfg.OCSF.Enabled {
		sink, err := buildAuditOCSFSink(cfg.OCSF)
		if err != nil {
			return nil, fmt.Errorf("audit.ocsf: %w", err)
		}
		sinks = append(sinks, sink)
		logger.Info("audit: ocsf sink enabled", "output", cfg.OCSF.Output)
	}
	if cfg.Syslog.Enabled {
		sink, err := buildAuditSyslogSink(cfg.Syslog)
		if err != nil {
			return nil, fmt.Errorf("audit.syslog: %w", err)
		}
		sinks = append(sinks, sink)
		logger.Info("audit: syslog sink enabled", "output", cfg.Syslog.Output, "facility", cfg.Syslog.Facility)
	}
	return sinks, nil
}
