package sso

import "github.com/snaplink/sso/spi"

import (
	"net/http"
	"strings"
)

// AuthMiddleware validates Bearer tokens on protected routes.
func AuthMiddleware(tokenIssuer TokenIssuer) MiddlewareFunc {
	return func(ctx HandlerContext) {
		auth := ctx.Request().Header.Get(HeaderAuthorization)
		if auth == "" || !strings.HasPrefix(auth, BearerPrefix) {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrUnauthorized))
			return
		}

		token := strings.TrimPrefix(auth, BearerPrefix)
		if _, err := tokenIssuer.Validate(ctx.Request().Context(), token); err != nil {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
			return
		}
	}
}

// CORS adds CORS headers to responses.
func CORS(allowedOrigins []string) MiddlewareFunc {
	return func(ctx HandlerContext) {
		w := ctx.ResponseWriter()
		origin := ctx.Request().Header.Get("Origin")

		for _, o := range allowedOrigins {
			if o == CORSAllowAllOrigin || o == origin {
				w.Header().Set(HeaderAccessControlOrigin, o)
				break
			}
		}

		w.Header().Set(HeaderAccessControlMethods, CORSAllowedMethods)
		w.Header().Set(HeaderAccessControlHeaders, CORSAllowedHeaders)

		if ctx.Request().Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
}

// LoggerMiddleware logs each request.
func LoggerMiddleware(l spi.Logger) MiddlewareFunc {
	return func(ctx HandlerContext) {
		l.Info("request",
			"method", ctx.Request().Method,
			"path", ctx.Request().URL.Path,
		)
	}
}
