// An hq-interop client built on golang.org/x/net/quic, the Go team's own QUIC
// implementation, as a second foreign peer for hq_server. It is independent of
// tools/interop_go (quic-go): a failure in one says nothing about the other.
//
// Usage: interop_go_xnet <port> <path>. It connects to 127.0.0.1:<port> with
// ALPN "hq-interop" and no certificate verification (the server's fixture is
// self-signed: this is a loopback check, not a policy to copy), opens one
// bidirectional stream, writes `GET /<path>\r\n`, closes the write side, reads
// the response to the end and prints it, then closes the connection with
// NO_ERROR.
//
// x/net/quic is experimental and its API is subject to change; go.mod pins the
// version this compiles against.
//
// Run it with `just interop-go-xnet`.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/net/quic"
)

const alpn = "hq-interop"

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: interop_go_xnet <port> <path>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "interop_go_xnet:", err)
		os.Exit(1)
	}
}

func run(port, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A nil config makes an endpoint that dials and never accepts.
	endpoint, err := quic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer endpoint.Close(ctx)

	conn, err := endpoint.Dial(ctx, "udp", "127.0.0.1:"+port, &quic.Config{
		TLSConfig: &tls.Config{
			// x/net/quic refuses a config that does not say TLS 1.3, which
			// QUIC requires anyway (RFC 9001 §4.2).
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			NextProtos:         []string{alpn},
		},
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Close sends a CONNECTION_CLOSE of NO_ERROR, then waits for the drain.
	defer conn.Close()

	stream, err := conn.NewStream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	stream.SetReadContext(ctx)
	stream.SetWriteContext(ctx)
	if _, err := fmt.Fprintf(stream, "GET /%s\r\n", strings.TrimPrefix(path, "/")); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if err := stream.CloseWrite(); err != nil {
		return fmt.Errorf("close write side: %w", err)
	}

	body, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	os.Stdout.Write(body)
	return nil
}
