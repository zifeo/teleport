/*
Copyright 2019-2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

func TestUserMessageFromError(t *testing.T) {
	t.Parallel()

	t.Skip("Enable after https://drone.gravitational.io/gravitational/teleport/3517 is merged.")
	tests := []struct {
		comment   string
		inError   error
		outString string
	}{
		{
			comment:   "outputs x509-specific unknown authority message",
			inError:   trace.Wrap(x509.UnknownAuthorityError{}),
			outString: "WARNING:\n\n  The proxy you are connecting to has presented a",
		},
		{
			comment:   "outputs x509-specific invalid certificate message",
			inError:   trace.Wrap(x509.CertificateInvalidError{}),
			outString: "WARNING:\n\n  The certificate presented by the proxy is invalid",
		},
		{
			comment:   "outputs user message as provided",
			inError:   trace.Errorf("\x1b[1mWARNING\x1b[0m"),
			outString: `error: "\x1b[1mWARNING\x1b[0m"`,
		},
	}

	for _, tt := range tests {
		message := UserMessageFromError(tt.inError)
		require.True(t, strings.HasPrefix(message, tt.outString), tt.comment)
	}
}

// TestEscapeControl tests escape control
func TestEscapeControl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in  string
		out string
	}{
		{
			in:  "hello, world!",
			out: "hello, world!",
		},
		{
			in:  "hello,\nworld!",
			out: `"hello,\nworld!"`,
		},
		{
			in:  "hello,\r\tworld!",
			out: `"hello,\r\tworld!"`,
		},
	}

	for i, tt := range tests {
		require.Equal(t, tt.out, EscapeControl(tt.in), fmt.Sprintf("test case %v", i))
	}
}

// TestAllowWhitespace tests escape control that allows (some) whitespace characters.
func TestAllowWhitespace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in  string
		out string
	}{
		{
			in:  "hello, world!",
			out: "hello, world!",
		},
		{
			in:  "hello,\nworld!",
			out: "hello,\nworld!",
		},
		{
			in:  "\thello, world!",
			out: "\thello, world!",
		},
		{
			in:  "\t\thello, world!",
			out: "\t\thello, world!",
		},
		{
			in:  "hello, world!\n",
			out: "hello, world!\n",
		},
		{
			in:  "hello, world!\n\n",
			out: "hello, world!\n\n",
		},
		{
			in:  string([]byte{0x68, 0x00, 0x68}),
			out: "\"h\\x00h\"",
		},
		{
			in:  string([]byte{0x68, 0x08, 0x68}),
			out: "\"h\\bh\"",
		},
		{
			in:  string([]int32{0x00000008, 0x00000009, 0x00000068}),
			out: "\"\\b\"\th",
		},
		{
			in:  string([]int32{0x00000090}),
			out: "\"\\u0090\"",
		},
		{
			in:  "hello,\r\tworld!",
			out: `"hello,\r"` + "\tworld!",
		},
		{
			in:  "hello,\n\r\tworld!",
			out: "hello,\n" + `"\r"` + "\tworld!",
		},
		{
			in:  "hello,\t\n\r\tworld!",
			out: "hello,\t\n" + `"\r"` + "\tworld!",
		},
	}

	for i, tt := range tests {
		require.Equal(t, tt.out, AllowWhitespace(tt.in), fmt.Sprintf("test case %v", i))
	}
}

func BenchmarkLogger(b *testing.B) {
	textLogger := slog.New(NewSLogTextHandler(io.Discard, slog.LevelDebug, NewDefaultTextFormatter(true))).With(trace.Component, "test")
	jsonLogger := slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case trace.Component:
				a.Key = "component"
			case slog.LevelKey:
				a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
			case slog.TimeKey:
				a.Key = "timestamp"
				a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
			case slog.SourceKey:
				s := a.Value.Any().(*slog.Source)
				count := 0
				idx := strings.LastIndexFunc(s.File, func(r rune) bool {
					if r == '/' {
						count++
					}

					return count == 2
				})
				a = slog.String("caller", fmt.Sprintf("%s:%d", s.File[idx+1:], s.Line))
			case slog.MessageKey:
				a.Key = "message"
			}

			return a
		},
	})).With(trace.Component, "test")

	addr := NetAddr{Addr: "127.0.0.1:1234", AddrNetwork: "tcp"}
	b.ResetTimer()

	err := errors.New("you can't do that")

	b.Run("text", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			textLogger.
				With("test", 123, "animal", "llama").
				With("error", err).
				Info("Adding diagnostic debugging handlers. To connect with profiler, use `go tool pprof diag_addr`\n.", "diag_addr", &addr)
		}
	})

	b.Run("json", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			jsonLogger.
				With("test", 123, "animal", "llama").
				With("error", err).
				Info("Adding diagnostic debugging handlers. To connect with profiler, use `go tool pprof <diag_addr>`.", "diag_addr", &addr)
		}
	})

}
