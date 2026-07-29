package tcp

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	tcpmiddleware "github.com/traefik/traefik/v3/pkg/server/middleware/tcp"
	"github.com/traefik/traefik/v3/pkg/server/service/tcp"
	tcp2 "github.com/traefik/traefik/v3/pkg/tcp"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/tls/generate"
	"github.com/traefik/traefik/v3/pkg/types"
)

// countingConn counts the bytes the server sends back, so a test can assert that
// the client never received a ServerHello.
type countingConn struct {
	net.Conn

	read atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

// buildDropRouter builds an entrypoint router from a catch-all TCP router, with
// passthrough and the middleware list controlled by the caller.
// backend is the address the catch-all service forwards to.
func buildDropRouter(t *testing.T, passthrough bool, middlewares []string, backend string) *Router {
	t.Helper()

	conf := &runtime.Configuration{
		TCPServices: map[string]*runtime.TCPServiceInfo{
			"dropped@file": {
				TCPService: &dynamic.TCPService{
					LoadBalancer: &dynamic.TCPServersLoadBalancer{
						Servers: []dynamic.TCPServer{{Address: backend}},
					},
				},
			},
		},
		TCPRouters: map[string]*runtime.TCPRouterInfo{
			"catchall@file": {
				TCPRouter: &dynamic.TCPRouter{
					EntryPoints: []string{"web"},
					Rule:        "HostSNI(`*`)",
					Service:     "dropped",
					Middlewares: middlewares,
					TLS:         &dynamic.RouterTCPTLSConfig{Passthrough: passthrough},
				},
			},
		},
		TCPMiddlewares: map[string]*runtime.TCPMiddlewareInfo{
			"drop@file": {
				TCPMiddleware: &dynamic.TCPMiddleware{Drop: &dynamic.TCPDrop{}},
			},
		},
	}

	dialerManager := tcp2.NewDialerManager(nil)
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"default@internal": {}})

	serviceManager := tcp.NewManager(conf, dialerManager)

	certPEM, keyPEM, err := generate.KeyPair("unknown.example.com", time.Time{})
	require.NoError(t, err)

	tlsManager := traefiktls.NewManager(nil)
	tlsManager.UpdateConfigs(
		t.Context(),
		map[string]traefiktls.Store{"default": {}},
		map[string]traefiktls.Options{"default": {}},
		[]*traefiktls.CertAndStores{{
			Certificate: traefiktls.Certificate{
				CertFile: types.FileOrContent(certPEM),
				KeyFile:  types.FileOrContent(keyPEM),
			},
			Stores: []string{"default"},
		}})

	middlewaresBuilder := tcpmiddleware.NewBuilder(conf.TCPMiddlewares)

	routerManager := NewManager(conf, serviceManager, middlewaresBuilder, nil, nil, tlsManager, nil)

	routers := routerManager.BuildHandlers(t.Context(), []string{"web"})

	for name, r := range conf.TCPRouters {
		require.Empty(t, r.Err, "router %s has errors", name)
	}

	router, ok := routers["web"]
	require.True(t, ok)

	return router
}

// handshakeAgainst drives a TLS ClientHello at the router and reports how many bytes
// the server sent back before the connection went away.
func handshakeAgainst(t *testing.T, router *Router, serverName string, protos []string) (int64, error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		router.ServeTCP(conn.(*net.TCPConn))
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawConn.Close() })

	require.NoError(t, rawConn.SetDeadline(time.Now().Add(5*time.Second)))

	counted := &countingConn{Conn: rawConn}

	tlsClient := tls.Client(counted, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         protos,
	})

	handshakeErr := tlsClient.Handshake()

	return counted.read.Load(), handshakeErr
}

// echoBackend is a TCP server that completes a read, so a router forwarding to it
// drives the lazy TLS handshake to completion.
func echoBackend(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("OK"))
			}()
		}
	}()

	return ln.Addr().String()
}

// C6: on a passthrough router the drop middleware runs before the handshake,
// so the client never receives a ServerHello.
func TestDrop_TCPPassthrough_NoServerHello(t *testing.T) {
	router := buildDropRouter(t, true, []string{"drop"}, echoBackend(t))

	read, err := handshakeAgainst(t, router, "unknown.example.com", nil)

	t.Logf("bytes received from server: %d, handshake err: %v", read, err)

	require.Error(t, err)
	assert.Zero(t, read)
}

// C6 also holds with TLS termination: tcp.TLSHandler wraps the connection in tls.Server
// but never calls Handshake (pkg/tcp/tls.go), and Go performs the handshake lazily on the
// first Read or Write. Because drop closes without doing either, no ServerHello is sent.
func TestDrop_TCPTermination_NoServerHello(t *testing.T) {
	router := buildDropRouter(t, false, []string{"drop"}, echoBackend(t))

	read, err := handshakeAgainst(t, router, "unknown.example.com", nil)

	t.Logf("bytes received from server: %d, handshake err: %v", read, err)

	require.Error(t, err)
	assert.Zero(t, read)
}

// Control for the two tests above: without the drop middleware the very same terminating
// router completes the handshake, proving the zero byte counts come from drop and not from
// a router that failed to build.
func TestDrop_TCPTermination_HandshakeWithoutDrop(t *testing.T) {
	router := buildDropRouter(t, false, nil, echoBackend(t))

	read, err := handshakeAgainst(t, router, "unknown.example.com", nil)

	t.Logf("bytes received from server: %d, handshake err: %v", read, err)

	require.NoError(t, err)
	assert.Positive(t, read)
}

// C8: a drop-only router still needs a service, so a catch-all cannot be declared
// with the middleware alone. A service with an empty server list is accepted.
func TestDrop_TCPRouterRequiresService(t *testing.T) {
	conf := &runtime.Configuration{
		TCPServices: map[string]*runtime.TCPServiceInfo{},
		TCPRouters: map[string]*runtime.TCPRouterInfo{
			"catchall@file": {
				TCPRouter: &dynamic.TCPRouter{
					EntryPoints: []string{"web"},
					Rule:        "HostSNI(`*`)",
					Middlewares: []string{"drop"},
					TLS:         &dynamic.RouterTCPTLSConfig{Passthrough: true},
				},
			},
		},
		TCPMiddlewares: map[string]*runtime.TCPMiddlewareInfo{
			"drop@file": {TCPMiddleware: &dynamic.TCPMiddleware{Drop: &dynamic.TCPDrop{}}},
		},
	}

	dialerManager := tcp2.NewDialerManager(nil)
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"default@internal": {}})

	tlsManager := traefiktls.NewManager(nil)
	tlsManager.UpdateConfigs(t.Context(), map[string]traefiktls.Store{}, map[string]traefiktls.Options{"default": {}}, nil)

	routerManager := NewManager(conf, tcp.NewManager(conf, dialerManager),
		tcpmiddleware.NewBuilder(conf.TCPMiddlewares), nil, nil, tlsManager, nil)

	_ = routerManager.BuildHandlers(t.Context(), []string{"web"})

	t.Logf("router errors: %v", conf.TCPRouters["catchall@file"].Err)
	assert.NotEmpty(t, conf.TCPRouters["catchall@file"].Err)
}

// C7: a catch-all drop router does not shadow the ACME TLS-ALPN-01 challenge,
// which is handled before any muxer match (pkg/server/router/tcp/router.go).
func TestDrop_TCPPassthrough_DoesNotShadowACME(t *testing.T) {
	router := buildDropRouter(t, true, []string{"drop"}, echoBackend(t))

	read, err := handshakeAgainst(t, router, "unknown.example.com", []string{"acme-tls/1"})

	t.Logf("bytes received from server: %d, handshake err: %v", read, err)

	// Without an ACME TLS config the challenge handler is brokenTLSRouter, which still
	// takes precedence over the catch-all. What matters is that the connection reached the
	// ACME handler rather than being dropped: the drop middleware sends nothing at all.
	require.Error(t, err)
	assert.Positive(t, read)
}
