package serverbuildplatform

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/releases"
	"github.com/yangwb1123/snaplink/shared/spi"

	releasedocker "github.com/yangwb1123/snaplink/platform/releases/pinnerdocker"

	releasenoop "github.com/yangwb1123/snaplink/platform/releases/pinnernoop"

	releasestatic "github.com/yangwb1123/snaplink/platform/releases/pinnerstatic"

	releasehttpprobe "github.com/yangwb1123/snaplink/platform/releases/probehttp"

	releasefile "github.com/yangwb1123/snaplink/platform/releases/storefile"

	releasememory "github.com/yangwb1123/snaplink/platform/releases/storememory"
)

func BuildReleaseSubsystem(cfg *config.Config, logger spi.Logger) (*releases.Registry, releases.ReleaseStore, error) {
	if !cfg.Releases.Enabled {
		return nil, nil, nil
	}
	store, err := buildReleaseStore(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	pinner, err := buildReleasePinner(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	probe, err := buildReleaseProbe(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	return &releases.Registry{
		Store:        store,
		Pinner:       pinner,
		Probe:        probe,
		ProbePolls:   cfg.Releases.Probe.Polls,
		ProbeBackoff: cfg.Releases.Probe.Backoff,
	}, store, nil
}

func buildReleaseStore(cfg *config.Config, logger spi.Logger) (releases.ReleaseStore, error) {
	switch strings.ToLower(cfg.Releases.Store.Backend) {
	case "", "file":
		dir := cfg.Releases.Store.File.Dir
		if dir == "" {
			dir = "./releases"
		}
		s, err := releasefile.New(dir)
		if err != nil {
			return nil, fmt.Errorf("release file store: %w", err)
		}
		logger.Info("release store: file", "dir", dir)
		return s, nil
	case "memory":
		logger.Info("release store: memory (in-process)")
		return releasememory.New(), nil
	default:
		return nil, fmt.Errorf("unknown releases.store.backend %q", cfg.Releases.Store.Backend)
	}
}

func buildReleasePinner(cfg *config.Config, logger spi.Logger) (releases.Pinner, error) {
	switch strings.ToLower(cfg.Releases.Pinner.Backend) {
	case "", "noop":
		logger.Info("release pinner: noop")
		return releasenoop.Pinner{Logger: logger.Info}, nil
	case "static":
		dir := cfg.Releases.Pinner.Static.BundleDir
		if dir == "" {
			return nil, errors.New("releases.pinner.backend=static requires releases.pinner.static.bundle_dir")
		}
		p, err := releasestatic.New(dir)
		if err != nil {
			return nil, fmt.Errorf("release static pinner: %w", err)
		}
		logger.Info("release pinner: static", "bundle_dir", dir)
		return p, nil
	case "docker":
		dir := cfg.Releases.Pinner.Docker.BundleDir
		if dir == "" {
			return nil, errors.New("releases.pinner.backend=docker requires releases.pinner.docker.bundle_dir")
		}
		p, err := releasedocker.New(dir)
		if err != nil {
			return nil, fmt.Errorf("release docker pinner: %w", err)
		}
		if c := cfg.Releases.Pinner.Docker.Cmd; c != "" {
			p.Cmd = c
		}
		logger.Info("release pinner: docker", "bundle_dir", dir, "cmd", p.Cmd)
		return p, nil
	default:
		return nil, fmt.Errorf("unknown releases.pinner.backend %q", cfg.Releases.Pinner.Backend)
	}
}

func buildReleaseProbe(cfg *config.Config, logger spi.Logger) (releases.HealthProbe, error) {
	switch strings.ToLower(cfg.Releases.Probe.Backend) {
	case "":
		// no probe; forward Pin always succeeds even if the new release is unhealthy
		return nil, nil
	case "http":
		url := cfg.Releases.Probe.HTTP.URL
		if url == "" {
			return nil, errors.New("releases.probe.backend=http requires releases.probe.http.url")
		}
		logger.Info("release probe: http", "url", url)
		return releasehttpprobe.New(url), nil
	default:
		return nil, fmt.Errorf("unknown releases.probe.backend %q", cfg.Releases.Probe.Backend)
	}
}
