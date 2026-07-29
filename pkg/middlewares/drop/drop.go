package drop

import (
	"context"
	"net/http"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"github.com/traefik/traefik/v3/pkg/middlewares/observability"
)

const (
	typeName = "Drop"
)

// drop is a middleware that closes the connection without sending any response.
type drop struct {
	next http.Handler
	name string
}

// New creates a new handler.
func New(ctx context.Context, next http.Handler, config dynamic.Drop, name string) (http.Handler, error) {
	logger := middlewares.GetLogger(ctx, name, typeName)
	logger.Debug().Msg("Creating middleware")

	return &drop{next: next, name: name}, nil
}

func (d *drop) GetTracingInformation() (string, string) {
	return d.name, typeName
}

func (d *drop) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := middlewares.GetLogger(req.Context(), d.name, typeName)
	logger.Debug().Msg("Dropping request")

	observability.SetStatusErrorf(req.Context(), "Dropping request")

	// The recovery middleware translates this sentinel into http.ErrAbortHandler, which makes the
	// server abort the response without writing anything: the connection is closed for HTTP/1.x,
	// and the stream is reset for HTTP/2.
	// http.ErrAbortHandler cannot be used directly here, because recovery turns it into a 500
	// when the response has not started yet.
	// The next handler is intentionally never called.
	panic(middlewares.ErrDrop)
}
