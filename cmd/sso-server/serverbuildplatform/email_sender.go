package serverbuildplatform

import (
	"context"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/emailsmtp"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/lifecycle/notification"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/platform/sse"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
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
		TLSMode:      cfg.TLSMode,
		Timeout:      cfg.Timeout,
		TemplatesDir: cfg.TemplatesDir,
		LinkBaseURL:  cfg.LinkBaseURL,
	}, log)
}

// BuildNotifications resolves the inbox stores, delivery channels, and audit router.
func BuildNotifications(cfg config.NotificationsConfig, users core.UserProvider, sessions core.SessionManager, email *emailsmtp.Sender,
	m *metrics.Metrics, log spi.Logger, rdb goredis.Cmdable) ([]sso.Option, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	store, prefs, err := resolveNotificationStores(cfg)
	if err != nil {
		return nil, err
	}
	senders := map[core.NotificationChannel]core.NotificationSender{core.NotificationChannelInApp: store.(core.NotificationSender)}
	// Cluster-shared cooldown: with a Redis client wired, the per-{subject,
	// type} suppression window is agreed across replicas (two replicas
	// seeing the same audit event no longer each pass their own local
	// cooldown and send a duplicate notice). Nil rdb keeps the in-process
	// map (byte-identical).
	if cfg.EmailEnabled && email != nil && users != nil {
		senders[core.NotificationChannelEmail] = emailsmtp.NewNotificationSender(email, func(ctx context.Context, subjectID string) (string, error) {
			user, err := users.GetByID(ctx, subjectID)
			if err != nil {
				return "", err
			}
			return user.Email, nil
		})
	}
	routerOpts := []notification.Option{
		notification.WithCooldown(cfg.Cooldown),
		notification.WithQueueSize(cfg.QueueSize), notification.WithWorkers(cfg.Workers),
		notification.WithObserver(m.ObserveNotificationDelivery),
		notification.WithUserProvider(users),
		notification.WithSessionExpiry(sessions, cfg.SessionExpiryWarning, cfg.SessionScanInterval),
		notification.WithBroker(sse.NewBroker(sse.Options{MaxSubscribers: 1024})),
	}
	routerOpts = append(routerOpts, sharedCooldownOption(rdb)...)
	router := notification.NewRouter(nil, prefs, senders, log, routerOpts...)
	return []sso.Option{sso.WithNotificationStore(store, prefs), sso.WithNotificationRouter(router)}, nil
}

// sharedCooldownOption returns the cluster-shared cooldown store option when
// a Redis client is wired: the per-{subject,type} suppression window is then
// agreed across replicas, so two replicas seeing the same audit event no
// longer each pass their own local cooldown and send a duplicate notice.
// Nil rdb keeps the router's in-process map (byte-identical).
func sharedCooldownOption(rdb goredis.Cmdable) []notification.Option {
	if rdb == nil {
		return nil
	}
	return []notification.Option{notification.WithCooldownStore(redisbackend.NewNotificationCooldown(rdb))}
}

// resolveNotificationStores builds the inbox + preference stores for the
// configured notification backend.
func resolveNotificationStores(cfg config.NotificationsConfig) (core.NotificationStore, core.NotificationPreferenceStore, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		memory := defaultimpl.NewMemoryNotificationStore()
		return memory, memory.PreferenceStore(), nil
	case "sqlite":
		inbox, err := sqlitestores.NewNotificationStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, nil, err
		}
		preferences, err := sqlitestores.NewNotificationPreferenceStore(cfg.SQLite.DSN)
		if err != nil {
			_ = inbox.Close()
			return nil, nil, err
		}
		return inbox, preferences, nil
	default:
		return nil, nil, fmt.Errorf("unsupported notification backend %q", cfg.Backend)
	}
}
