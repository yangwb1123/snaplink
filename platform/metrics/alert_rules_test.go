package metrics_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/yangwb1123/snaplink/platform/metrics"
)

// The compose observability profile bind-mounts these artifacts straight
// into Prometheus/Grafana (ops/deploy/compose/compose.yaml), so a renamed
// metric or malformed file fails silently at container start. This gate
// cross-references them against the metric-name wire constants.
const (
	alertRulesPath = "../../ops/deploy/grafana/alerts.yaml"
	dashboardPath  = "../../ops/deploy/grafana/sso-overview.json"
)

type promRule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type promRuleFile struct {
	Groups []struct {
		Name  string     `yaml:"name"`
		Rules []promRule `yaml:"rules"`
	} `yaml:"groups"`
}

func loadAlertRules(t *testing.T) map[string]promRule {
	t.Helper()
	raw, err := os.ReadFile(alertRulesPath)
	if err != nil {
		t.Fatalf("read %s: %v", alertRulesPath, err)
	}
	var f promRuleFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse %s: %v", alertRulesPath, err)
	}
	rules := make(map[string]promRule)
	for _, g := range f.Groups {
		for _, r := range g.Rules {
			rules[r.Alert] = r
		}
	}
	return rules
}

func TestDeployAlerts_AuditLossAndSigningDegradationCovered(t *testing.T) {
	t.Parallel()
	rules := loadAlertRules(t)
	want := map[string][]string{
		"SSOAuditEventsDropped": {
			metrics.NameAuditAsyncDropsQueueFull,
			metrics.NameAuditAsyncDropsClosed,
			metrics.NameAuditAsyncDropsInnerError,
		},
		"SSOAuditQueueSaturated": {
			metrics.NameAuditAsyncQueueDepth,
			metrics.NameAuditAsyncQueueCapacity,
		},
		"SSOSigningBackendDown":            {metrics.NameSigningBackendUp},
		"SSOSigningKeyAggregationDegraded": {metrics.NameSigningKeyAggregationUp},
	}
	for name, metricNames := range want {
		r, ok := rules[name]
		if !ok {
			t.Errorf("alert %q missing from %s", name, alertRulesPath)
			continue
		}
		for _, m := range metricNames {
			if !strings.Contains(r.Expr, m) {
				t.Errorf("alert %q expr does not reference %s:\n%s", name, m, r.Expr)
			}
		}
	}
}

func TestDeployAlerts_ConventionsHold(t *testing.T) {
	t.Parallel()
	validSeverity := map[string]bool{"info": true, "warning": true, "critical": true}
	validComponent := map[string]bool{"sso-server": true, "snaplink-billing": true}
	for name, r := range loadAlertRules(t) {
		if !validSeverity[r.Labels["severity"]] {
			t.Errorf("alert %q severity %q not in info|warning|critical", name, r.Labels["severity"])
		}
		if !validComponent[r.Labels["component"]] {
			t.Errorf("alert %q component %q is not a deployed service", name, r.Labels["component"])
		}
		if r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
			t.Errorf("alert %q missing summary/description annotation", name)
		}
	}
}

func TestDeployDashboard_AuditAndSigningPanelsPresent(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read %s: %v", dashboardPath, err)
	}
	var dash struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("parse %s: %v", dashboardPath, err)
	}
	var all strings.Builder
	for _, p := range dash.Panels {
		for _, tg := range p.Targets {
			all.WriteString(tg.Expr)
			all.WriteString("\n")
		}
	}
	exprs := all.String()
	for _, m := range []string{
		metrics.NameAuditAsyncDropsQueueFull,
		metrics.NameAuditAsyncDropsClosed,
		metrics.NameAuditAsyncDropsInnerError,
		metrics.NameAuditAsyncQueueDepth,
		metrics.NameAuditAsyncQueueCapacity,
		metrics.NameSigningBackendUp,
		metrics.NameSigningKeyAggregationUp,
		metrics.NameSigningKeyAdoptionErrorsTotal,
	} {
		if !strings.Contains(exprs, m) {
			t.Errorf("no dashboard panel target references %s", m)
		}
	}
}
