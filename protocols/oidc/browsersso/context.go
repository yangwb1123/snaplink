package browsersso

import (
	"net/http"
	"slices"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// NonInteractive prevents prompt=none from exposing an MFA/consent UI or a
// one-use challenge. The existing authorization-delivery wrapper still owns
// issuer, state, redirect validation, JARM and form-post delivery.
func NonInteractive(ctx core.HandlerContext, prompt string) core.HandlerContext {
	if !slices.Contains(strings.Fields(prompt), core.PromptNone) {
		return ctx
	}
	return &nonInteractiveContext{HandlerContext: ctx}
}

type nonInteractiveContext struct{ core.HandlerContext }

func (c *nonInteractiveContext) JSON(status int, value any) {
	errorCode := ""
	switch body := value.(type) {
	case map[string]string:
		errorCode = body[core.KeyError]
	case map[string]any:
		errorCode, _ = body[core.KeyError].(string)
	}
	if errorCode == core.ErrMFARequired || errorCode == core.ErrConsentRequired {
		if errorCode == core.ErrMFARequired {
			errorCode = core.ErrInteractionRequired
		}
		body := map[string]any{core.KeyError: errorCode}
		copyPublicErrorFields(body, value)
		c.HandlerContext.JSON(http.StatusBadRequest, body)
		return
	}
	c.HandlerContext.JSON(status, value)
}

func copyPublicErrorFields(output map[string]any, value any) {
	for _, key := range []string{core.KeyIss, core.KeyState} {
		switch body := value.(type) {
		case map[string]string:
			if value, ok := body[key]; ok {
				output[key] = value
			}
		case map[string]any:
			if value, ok := body[key]; ok {
				output[key] = value
			}
		}
	}
}
