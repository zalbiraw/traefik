package middlewares

import (
	"context"
	"errors"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
)

// ErrDrop is a sentinel panic value signaling that the connection must be closed
// without sending anything to the client.
// It is distinct from http.ErrAbortHandler, which the recovery middleware turns into a 500
// when the response has not started yet.
var ErrDrop = errors.New("drop connection")

// GetLogger creates a logger with the middleware fields.
func GetLogger(ctx context.Context, middleware, middlewareType string) *zerolog.Logger {
	logger := log.Ctx(ctx).With().
		Str(logs.MiddlewareName, middleware).
		Str(logs.MiddlewareType, middlewareType).
		Logger()

	return &logger
}
