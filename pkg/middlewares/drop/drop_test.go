package drop

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containous/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares/accesslog"
	"github.com/traefik/traefik/v3/pkg/middlewares/capture"
	"github.com/traefik/traefik/v3/pkg/middlewares/observability"
	"github.com/traefik/traefik/v3/pkg/middlewares/recovery"
	otypes "github.com/traefik/traefik/v3/pkg/observability/types"
)

// newDrop builds the middleware in front of a handler that would otherwise answer 200,
// so that any response observed by the client proves the drop did not happen.
func newDrop(t *testing.T) http.Handler {
	t.Helper()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), next, dynamic.Drop{}, "dropTest")
	require.NoError(t, err)

	return handler
}

// newDropBehindRecovery reproduces the real chain: recovery.New is the outermost
// handler of every entrypoint (pkg/server/router/router.go).
func newDropBehindRecovery(t *testing.T) http.Handler {
	t.Helper()

	handler, err := recovery.New(context.Background(), newDrop(t))
	require.NoError(t, err)

	return handler
}

// readRawResponse sends a minimal HTTP/1.1 request over a raw connection,
// and reports how many bytes the server sent back.
func readRawResponse(t *testing.T, addr string) (int, error) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	t.Logf("read %d bytes, err=%v, body=%q", n, err, buf[:n])

	return n, err
}

// C1: zero response bytes over cleartext HTTP/1.1.
func TestDrop_HTTP1(t *testing.T) {
	server := httptest.NewServer(newDropBehindRecovery(t))
	t.Cleanup(server.Close)

	n, err := readRawResponse(t, server.Listener.Addr().String())

	assert.Zero(t, n)
	assert.Error(t, err)
}

// C3: same over TLS, without the middleware needing an http.Hijacker.
func TestDrop_HTTPS(t *testing.T) {
	server := httptest.NewTLSServer(newDropBehindRecovery(t))
	t.Cleanup(server.Close)

	resp, err := server.Client().Get(server.URL)
	if err == nil {
		defer resp.Body.Close()
	}

	t.Logf("resp=%v, err=%v", resp, err)

	require.Error(t, err)
	assert.Nil(t, resp)
}

// C2: over HTTP/2 the stream is reset instead of the connection being closed.
func TestDrop_HTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(newDropBehindRecovery(t))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	client := server.Client()

	resp, err := client.Get(server.URL)
	if err == nil {
		defer resp.Body.Close()
	}

	t.Logf("resp=%v, err=%v", resp, err)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "INTERNAL_ERROR")
}

// C4: the request is still access-logged even though nothing is sent to the client.
func TestDrop_IsAccessLogged(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access.log")

	logHandler, err := accesslog.NewHandler(t.Context(), &otypes.AccessLog{
		FilePath: logPath,
		Format:   accesslog.CommonFormat,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, logHandler.Close())
	})

	chain := alice.New()
	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return recovery.New(t.Context(), next)
	})
	chain = chain.Append(capture.Wrap)
	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return observability.WithObservabilityHandler(next, observability.Observability{
			AccessLogsEnabled: true,
		}), nil
	})
	chain = chain.Append(logHandler.AliceConstructor())

	handler, err := chain.Then(newDrop(t))
	require.NoError(t, err)

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	n, err := readRawResponse(t, server.Listener.Addr().String())
	assert.Zero(t, n)
	assert.Error(t, err)

	// The log is written while the panic unwinds, so give the handler a moment to flush.
	require.Eventually(t, func() bool {
		content, readErr := os.ReadFile(logPath)
		return readErr == nil && len(content) > 0
	}, 5*time.Second, 50*time.Millisecond)

	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	t.Logf("access log: %s", content)
	assert.Contains(t, string(content), "GET / HTTP/1.1")
}
