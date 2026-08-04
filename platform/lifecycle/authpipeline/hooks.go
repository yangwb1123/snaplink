package authpipeline

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/wasmauthz"
	"github.com/yangwb1123/snaplink/shared/core"
)

// NewIPSkipMFAHook trusts the configured CIDRs to bypass MFA challenges after
// primary authentication. Risk and conditional-access deny verdicts still win.
func NewIPSkipMFAHook(cidrs []string) (core.AuthHook, error) {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	return core.AuthHookFunc{
		At:     core.PhasePostAuthenticate,
		Config: core.AuthHookConfig{Name: "builtin.ip_skip_mfa", Priority: 10, FailClosed: true},
		Run: func(_ context.Context, input *core.HookInput) (*core.HookOutput, error) {
			ip := net.ParseIP(input.IP)
			for _, network := range networks {
				if ip != nil && network.Contains(ip) {
					return &core.HookOutput{SkipMFA: true}, nil
				}
			}
			return nil, nil
		},
	}, nil
}

// NewProfileCompletionHook rejects authenticated profiles missing a required
// non-empty attribute before any session or token side effect occurs.
func NewProfileCompletionHook(required []string) core.AuthHook {
	fields := append([]string(nil), required...)
	return core.AuthHookFunc{
		At:     core.PhasePostAuthenticate,
		Config: core.AuthHookConfig{Name: "builtin.profile_completion", Priority: 20, FailClosed: true},
		Run: func(_ context.Context, input *core.HookInput) (*core.HookOutput, error) {
			if input.AuthResult == nil {
				return nil, core.NewAuthHookError(core.ErrProfileIncomplete, http.StatusForbidden, errors.New("missing authentication result"))
			}
			for _, field := range fields {
				if strings.TrimSpace(input.AuthResult.Attributes[field]) == "" {
					return nil, core.NewAuthHookError(core.ErrProfileIncomplete, http.StatusForbidden, errors.New("required profile attribute missing"))
				}
			}
			return nil, nil
		},
	}
}

// NewSIEMFailureHook sends login failures asynchronously through a bounded
// concurrency gate. Saturation is reported as a hook error but the notification
// phase always fails open, so login responses are never delayed or changed.
func NewSIEMFailureHook(notify func(context.Context, *core.HookInput) error, concurrency int, timeout time.Duration) core.AuthHook {
	if concurrency <= 0 {
		concurrency = 4
	}
	if timeout <= 0 {
		timeout = core.DefaultAuthHookTimeout
	}
	semaphore := make(chan struct{}, concurrency)
	return core.AuthHookFunc{
		At:     core.PhaseOnLoginFailed,
		Config: core.AuthHookConfig{Name: "builtin.siem_login_failure", Priority: 100, Timeout: time.Second},
		Run: func(_ context.Context, input *core.HookInput) (*core.HookOutput, error) {
			select {
			case semaphore <- struct{}{}:
				go notifySIEM(notify, input, semaphore, timeout)
				return nil, nil
			default:
				return nil, errors.New("siem notification queue saturated")
			}
		},
	}
}

func notifySIEM(notify func(context.Context, *core.HookInput) error, input *core.HookInput, semaphore chan struct{}, timeout time.Duration) {
	defer func() { <-semaphore }()
	if notify == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = notify(ctx, input)
}

// WASMAuthorizer is satisfied by wasmauthz.Engine and makes the adapter easy
// to test without loading a guest module.
type WASMAuthorizer interface {
	Authorize(context.Context, wasmauthz.Request) (wasmauthz.Decision, error)
}

// NewWASMHook adapts the existing policy-as-WASM engine to any lifecycle
// phase. A guest error or deny is a fail-closed hook rejection when configured.
func NewWASMHook(authorizer WASMAuthorizer, phase core.LoginPhase, config core.AuthHookConfig) core.AuthHook {
	if config.Name == "" {
		config.Name = "builtin.wasm"
	}
	return core.AuthHookFunc{
		At: phase, Config: config,
		Run: func(ctx context.Context, input *core.HookInput) (*core.HookOutput, error) {
			if authorizer == nil {
				return nil, core.NewAuthHookError(core.ErrAuthHookRejected, http.StatusForbidden, errors.New("wasm authorizer not configured"))
			}
			decision, err := authorizer.Authorize(ctx, wasmRequest(input))
			if err != nil {
				return nil, core.NewAuthHookError(core.ErrAuthHookRejected, http.StatusForbidden, err)
			}
			if !decision.Allowed {
				return nil, core.NewAuthHookError(core.ErrAuthHookRejected, http.StatusForbidden, errors.New("wasm policy denied"))
			}
			return nil, nil
		},
	}
}

func wasmRequest(input *core.HookInput) wasmauthz.Request {
	attributes := map[string]string{
		"client_id": input.ClientID, "tenant_id": input.TenantID,
		"provider": input.Provider, "ip": input.IP,
	}
	for key, value := range input.Headers {
		attributes["header."+strings.ToLower(key)] = value
	}
	return wasmauthz.Request{Subject: input.UserID, Action: string(input.Phase), Resource: input.ClientID, Context: attributes}
}
