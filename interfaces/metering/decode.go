package meteringhttp

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

var (
	errInvalidJSON  = errors.New("metering http: invalid JSON request")
	errBodyTooLarge = errors.New("metering http: request body too large")
)

func decodeStrictJSON(ctx core.HandlerContext, target any) error {
	mediaType, _, err := mime.ParseMediaType(ctx.Request().Header.Get(core.HeaderContentType))
	if err != nil || mediaType != core.ContentTypeJSON {
		return errInvalidJSON
	}
	body := http.MaxBytesReader(ctx.ResponseWriter(), ctx.Request().Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return normalizeDecodeError(err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return normalizeDecodeError(err)
	}
	return nil
}

func normalizeDecodeError(err error) error {
	var maximum *http.MaxBytesError
	if errors.As(err, &maximum) {
		return errBodyTooLarge
	}
	return errInvalidJSON
}

func validRequestID(value string, required bool) bool {
	if value == "" {
		return !required
	}
	return len(value) <= maxRequestIDLength && strings.TrimSpace(value) == value
}

func idempotencyKey(ctx core.HandlerContext) (string, bool) {
	value := ctx.Request().Header.Get(headerIdempotency)
	return value, value != "" && len(value) <= maxIdempotencyBytes && strings.TrimSpace(value) == value
}

func emptyRequestBody(ctx core.HandlerContext) bool {
	if ctx.Request().Body == nil || ctx.Request().Body == http.NoBody {
		return true
	}
	var one [1]byte
	_, err := ctx.Request().Body.Read(one[:])
	return errors.Is(err, io.EOF)
}
