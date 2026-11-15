// An hq-interop client built on quic-go, as a foreign peer for hq_server.
//
// Usage: interop_go <port> <path>. It connects to 127.0.0.1:<port> with ALPN
// "hq-interop" and no certificate verification (the server's fixture is
// self-signed: this is a loopback check, not a policy to copy), opens one
// bidirectional stream, writes `GET /<path>\r\n`, closes the write side, reads
// the response to the end and prints it, then closes the connection with
// NO_ERROR.
//
// This uses the raw quic package. hq-interop is not HTTP/3, so http3 is not
// imported.
//
// Run it with `just interop-go`.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const alpn = "hq-interop"

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: interop_go <port> <path>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "interop_go:", err)
		os.Exit(1)
	}
}

func run(port, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, "127.0.0.1:"+port, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
	}, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Application error code 0 is NO_ERROR.
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if _, err := fmt.Fprintf(stream, "GET /%s\r\n", strings.TrimPrefix(path, "/")); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close write side: %w", err)
	}

	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	body, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	os.Stdout.Write(body)
	return nil
}
