package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"time"
)

const (
	DefaultAuthHookTimeout = 5 * time.Second
	MaxAuthHooksPerPhase   = 32
)

// AuthHookError is the only hook error shape allowed onto the wire. Detail is
// intentionally kept internal; callers receive Code and Status only.
type AuthHookError struct {
	Code   string
	Status int
	Err    error
}

func (e *AuthHookError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("auth hook %s: %v", e.Code, e.Err)
	}
	return "auth hook " + e.Code
}

func (e *AuthHookError) Unwrap() error { return e.Err }

func NewAuthHookError(code string, status int, err error) error {
	if code == "" {
		code = ErrAuthHookRejected
	}
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	return &AuthHookError{Code: code, Status: status, Err: err}
}

// AuthHookHTTPError collapses arbitrary hook failures to stable wire values.
func AuthHookHTTPError(err error) (int, string, bool) {
	var hookErr *AuthHookError
	if !errors.As(err, &hookErr) {
		return 0, "", false
	}
	return hookErr.Status, hookErr.Code, true
}

type registeredAuthHook struct {
	hook   AuthHook
	config AuthHookConfig
	order  uint64
}

// AuthHookRegistry is safe for concurrent execution and startup registration.
type AuthHookRegistry struct {
	mu       sync.RWMutex
	hooks    map[LoginPhase][]registeredAuthHook
	next     uint64
	observer AuthHookObserver
}

func NewAuthHookRegistry(observer AuthHookObserver) *AuthHookRegistry {
	return &AuthHookRegistry{hooks: make(map[LoginPhase][]registeredAuthHook), observer: observer}
}

func (r *AuthHookRegistry) Register(hook AuthHook, explicit ...AuthHookConfig) error {
	if hook == nil || !validLoginPhase(hook.Phase()) {
		return errors.New("auth hook has an invalid phase")
	}
	config := resolveAuthHookConfig(hook, explicit)
	r.mu.Lock()
	defer r.mu.Unlock()
	phaseHooks := r.hooks[hook.Phase()]
	if len(phaseHooks) >= MaxAuthHooksPerPhase {
		return fmt.Errorf("auth hook phase %s exceeds limit %d", hook.Phase(), MaxAuthHooksPerPhase)
	}
	for _, existing := range phaseHooks {
		if existing.config.Name == config.Name {
			return fmt.Errorf("auth hook %q already registered for %s", config.Name, hook.Phase())
		}
	}
	r.next++
	phaseHooks = append(phaseHooks, registeredAuthHook{hook: hook, config: config, order: r.next})
	sort.SliceStable(phaseHooks, func(i, j int) bool {
		if phaseHooks[i].config.Priority == phaseHooks[j].config.Priority {
			return phaseHooks[i].order < phaseHooks[j].order
		}
		return phaseHooks[i].config.Priority < phaseHooks[j].config.Priority
	})
	r.hooks[hook.Phase()] = phaseHooks
	return nil
}

func (r *AuthHookRegistry) Has(phase LoginPhase) bool {
	return r != nil && len(r.snapshot(phase)) != 0
}

func (r *AuthHookRegistry) Execute(ctx context.Context, input *HookInput) (*HookOutput, error) {
	if r == nil || input == nil {
		return nil, nil
	}
	hooks := r.snapshot(input.Phase)
	merged := &HookOutput{}
	working := cloneHookInput(input)
	for _, entry := range hooks {
		out, err := r.executeOne(ctx, entry, cloneHookInput(working))
		if err != nil {
			if authHookContinues(input.Phase, entry.config) {
				continue
			}
			return nil, normalizeAuthHookError(err)
		}
		if err := mergeHookOutput(input.Phase, merged, out); err != nil {
			if authHookContinues(input.Phase, entry.config) {
				continue
			}
			return nil, normalizeAuthHookError(err)
		}
		applyHookOutput(working, out)
	}
	return merged, nil
}

func (r *AuthHookRegistry) snapshot(phase LoginPhase) []registeredAuthHook {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]registeredAuthHook(nil), r.hooks[phase]...)
}

type authHookResult struct {
	output *HookOutput
	err    error
}

func (r *AuthHookRegistry) executeOne(ctx context.Context, entry registeredAuthHook, input *HookInput) (*HookOutput, error) {
	started := time.Now()
	callCtx, cancel := context.WithTimeout(ctx, entry.config.Timeout)
	defer cancel()
	result := make(chan authHookResult, 1)
	go invokeAuthHook(callCtx, entry.hook, input, result)
	var output *HookOutput
	var err error
	select {
	case hookResult := <-result:
		output, err = hookResult.output, hookResult.err
	case <-callCtx.Done():
		err = NewAuthHookError(ErrAuthHookTimeout, http.StatusServiceUnavailable, callCtx.Err())
	}
	if err == nil {
		err = validateHookOutput(input.Phase, output)
	}
	continued := err == nil || authHookContinues(input.Phase, entry.config)
	r.observe(ctx, entry, input, time.Since(started), continued, err)
	return output, err
}

func invokeAuthHook(ctx context.Context, hook AuthHook, input *HookInput, result chan<- authHookResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result <- authHookResult{err: fmt.Errorf("auth hook panic: %v", recovered)}
		}
	}()
	output, err := hook.Execute(ctx, input)
	result <- authHookResult{output: output, err: err}
}

func (r *AuthHookRegistry) observe(ctx context.Context, entry registeredAuthHook, input *HookInput, duration time.Duration, continued bool, err error) {
	if r.observer == nil {
		return
	}
	code := ""
	if err != nil {
		_, code, _ = AuthHookHTTPError(normalizeAuthHookError(err))
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	r.observer(ctx, AuthHookExecution{Phase: input.Phase, Name: entry.config.Name, Duration: duration,
		Outcome: outcome, Continued: continued, Code: code, ClientID: input.ClientID,
		TenantID: input.TenantID, Provider: input.Provider, UserID: input.UserID, IP: input.IP})
}

func resolveAuthHookConfig(hook AuthHook, explicit []AuthHookConfig) AuthHookConfig {
	config := AuthHookConfig{}
	configured := false
	if provider, ok := hook.(AuthHookConfigurator); ok {
		config = provider.AuthHookConfig()
		configured = true
	}
	if len(explicit) != 0 {
		config = explicit[0]
		configured = true
	}
	if config.Name == "" {
		config.Name = reflect.TypeOf(hook).String()
	}
	if config.Timeout <= 0 {
		config.Timeout = DefaultAuthHookTimeout
	}
	if !configured && hook.Phase() != PhasePostTokenIssuance && hook.Phase() != PhaseOnLoginFailed {
		config.FailClosed = true
	}
	return config
}

func authHookContinues(phase LoginPhase, config AuthHookConfig) bool {
	return phase == PhasePostTokenIssuance || phase == PhaseOnLoginFailed || !config.FailClosed
}

func normalizeAuthHookError(err error) error {
	if _, _, ok := AuthHookHTTPError(err); ok {
		return err
	}
	return NewAuthHookError(ErrAuthHookRejected, http.StatusForbidden, err)
}

func mergeHookOutput(phase LoginPhase, merged, output *HookOutput) error {
	if err := validateHookOutput(phase, output); err != nil {
		return err
	}
	if output == nil {
		return nil
	}
	mergeStringMap(&merged.Attributes, output.Attributes)
	mergeStringMap(&merged.Claims, output.Claims)
	merged.SkipMFA = merged.SkipMFA || output.SkipMFA
	return nil
}

func validateHookOutput(phase LoginPhase, output *HookOutput) error {
	if output == nil {
		return nil
	}
	if phase != PhasePostAuthenticate && (len(output.Attributes) != 0 || output.SkipMFA) {
		return errors.New("auth hook returned authentication mutations in an incompatible phase")
	}
	if phase != PhasePreTokenIssuance && len(output.Claims) != 0 {
		return errors.New("auth hook returned token claims in an incompatible phase")
	}
	return nil
}

func mergeStringMap(target *map[string]string, additions map[string]string) {
	if len(additions) == 0 {
		return
	}
	if *target == nil {
		*target = make(map[string]string, len(additions))
	}
	for key, value := range additions {
		(*target)[key] = value
	}
}

func applyHookOutput(input *HookInput, output *HookOutput) {
	if output == nil {
		return
	}
	mergeStringMap(&input.Claims, output.Claims)
	if input.AuthResult != nil {
		mergeStringMap(&input.AuthResult.Attributes, output.Attributes)
	}
}

func validLoginPhase(phase LoginPhase) bool {
	switch phase {
	case PhasePreAuthenticate, PhasePostAuthenticate, PhasePreTokenIssuance,
		PhasePostTokenIssuance, PhaseOnLoginFailed:
		return true
	default:
		return false
	}
}

func cloneHookInput(input *HookInput) *HookInput {
	clone := *input
	clone.Headers = cloneStringMap(input.Headers)
	clone.Claims = cloneStringMap(input.Claims)
	clone.Scopes = append([]string(nil), input.Scopes...)
	clone.AuthResult = cloneAuthResult(input.AuthResult)
	if input.Token != nil {
		token := *input.Token
		clone.Token = &token
	}
	return &clone
}

func cloneAuthResult(input *AuthResult) *AuthResult {
	if input == nil {
		return nil
	}
	clone := *input
	clone.Attributes = cloneStringMap(input.Attributes)
	clone.AuthMethods = append([]string(nil), input.AuthMethods...)
	if input.CredentialHealth != nil {
		health := *input.CredentialHealth
		clone.CredentialHealth = &health
	}
	return &clone
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	clone := make(map[string]string, len(input))
	for key, value := range input {
		clone[key] = value
	}
	return clone
}
