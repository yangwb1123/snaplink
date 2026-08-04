// Package legacysync reconciles the legacy sv_sso directory and selected
// sv_auth application roles into an offline Snaplink SQLite deployment.
package legacysync

import (
	"context"
	"fmt"
	"io"
	"os"
)

// Run executes sso-ctl legacy-sync. Writes require the explicit --apply flag;
// omission performs a read-only dry-run against both source and target.
func Run(args []string) int {
	return run(args, os.Stdout, os.Stderr, os.Getenv)
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "sso-ctl legacy-sync: %v\n", err)
		return 2
	}
	password := getenv(passwordEnv)
	if password == "" {
		fmt.Fprintf(stderr, "sso-ctl legacy-sync: %s is required\n", passwordEnv)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	data, err := loadLegacyData(ctx, cfg, password)
	if err != nil {
		return reportError(stderr, err)
	}
	plan, err := buildPlan(data, cfg.AppMap, cfg.RoleMap, cfg.UserMap)
	if err != nil {
		return reportError(stderr, err)
	}
	targetDB, err := openTarget(ctx, cfg.TargetDSN, !cfg.Apply)
	if err != nil {
		return reportError(stderr, err)
	}
	defer func() { _ = targetDB.Close() }()
	target, err := inspectTarget(ctx, targetDB)
	if err != nil {
		return reportError(stderr, err)
	}
	mode := "dry-run"
	if cfg.Apply {
		mode = "applied"
	}
	report, err := buildReport(plan, target, mode)
	if err != nil {
		return reportError(stderr, err)
	}
	if cfg.Apply {
		if err := applyPlan(ctx, targetDB, plan, target); err != nil {
			return reportError(stderr, err)
		}
	}
	printReport(stdout, report)
	return 0
}

func reportError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "sso-ctl legacy-sync: %v\n", err)
	return 1
}

func printReport(out io.Writer, report syncReport) {
	fmt.Fprintf(out, "legacy-sync mode=%s\n", report.Mode)
	fmt.Fprintf(out, "source users=%d active=%d inactive=%d roles=%d grants=%d overrides=%d\n",
		report.Source.Users, report.Source.Active, report.Source.Inactive,
		report.Source.Roles, report.Source.Grants, report.Source.Overrides)
	fmt.Fprintf(out, "target create_users=%d update_users=%d deactivate_users=%d credentials=%d roles=%d assignments=%d\n",
		report.CreateUsers, report.UpdateUsers, report.DeactivateUsers,
		report.Credentials, report.Roles, report.Assignments)
}
