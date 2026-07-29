package drop

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

func TestDrop_ClosesWithoutWriting(t *testing.T) {
	next := tcp.HandlerFunc(func(conn tcp.WriteCloser) {
		_, _ = conn.Write([]byte("OK"))
		_ = conn.Close()
	})

	handler, err := New(t.Context(), next, dynamic.TCPDrop{}, "dropTest")
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handler.ServeTCP(conn.(*net.TCPConn))
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })

	require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(5*time.Second)))

	buf := make([]byte, 64)
	n, err := clientConn.Read(buf)

	assert.Zero(t, n)
	assert.ErrorIs(t, err, io.EOF)
}
