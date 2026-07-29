package drop

import (
	"context"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

const (
	typeName = "DropTCP"
)

// drop is a middleware that closes the connection without sending anything to the client.
type drop struct {
	next tcp.Handler
	name string
}

// New builds a new TCP Drop middleware.
func New(ctx context.Context, next tcp.Handler, config dynamic.TCPDrop, name string) (tcp.Handler, error) {
	logger := middlewares.GetLogger(ctx, name, typeName)
	logger.Debug().Msg("Creating middleware")

	return &drop{next: next, name: name}, nil
}

func (d *drop) ServeTCP(conn tcp.WriteCloser) {
	logger := middlewares.GetLogger(context.Background(), d.name, typeName)
	logger.Debug().Msgf("Dropping connection from %s", conn.RemoteAddr())

	// On a router without TLS termination (no TLS section, or TLS passthrough), this runs before
	// the TLS handshake, so the client never receives a ServerHello.
	// The next handler is intentionally never called.
	conn.Close()
}
