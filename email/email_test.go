package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deicod/auth/config"
	mail "github.com/wneessen/go-mail"
)

const (
	smtpTestUser = "sender@example.com"
	smtpTestPass = "smtp-test-password"
)

func TestSMTPAuthentication(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(certificateServer.Close)
	roots := x509.NewCertPool()
	roots.AddCert(certificateServer.Certificate())

	for _, tc := range []struct {
		name          string
		user          string
		pass          string
		advertiseAuth bool
		requireAuth   bool
		wantAuth      bool
		wantErr       bool
	}{
		{"credentials authenticate", smtpTestUser, smtpTestPass, true, true, true, false},
		{"bad password is rejected", smtpTestUser, "wrong-password", true, true, true, true},
		{"configured credentials require AUTH support", smtpTestUser, smtpTestPass, false, false, false, true},
		{"anonymous relay", "", "", false, false, false, false},
		{"sender without password uses relay", smtpTestUser, "", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := tls.Listen("tcp", "127.0.0.1:0", certificateServer.TLS.Clone())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			serverContext, stopServer := context.WithCancel(context.Background())
			t.Cleanup(stopServer)
			done := make(chan smtpResult, 1)
			go func() {
				done <- serveSMTP(serverContext, listener, tc.advertiseAuth, tc.requireAuth)
			}()

			host, portText, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			mailer := NewMailer(config.Mail{
				Host: host, Port: port, User: tc.user, Pass: tc.pass, UseSSL: true,
			})
			client, err := mailer.newClient()
			if err != nil {
				t.Fatal(err)
			}
			if err := client.SetTLSConfig(&tls.Config{
				RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12,
			}); err != nil {
				t.Fatal(err)
			}
			message := mail.NewMsg()
			if err := message.From(smtpTestUser); err != nil {
				t.Fatal(err)
			}
			if err := message.To("recipient@example.com"); err != nil {
				t.Fatal(err)
			}
			message.Subject("Verification transport test")
			message.SetBodyString(mail.TypeTextPlain, "Test verification message")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = client.DialAndSendWithContext(ctx, message)
			stopServer()
			if (err != nil) != tc.wantErr {
				t.Errorf("send error = %v, want error = %t", err, tc.wantErr)
			}
			result := <-done
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.authAttempted != tc.wantAuth {
				t.Errorf("SMTP AUTH attempted = %t, want %t", result.authAttempted, tc.wantAuth)
			}
			if result.accepted != !tc.wantErr {
				t.Errorf("message accepted = %t, want %t", result.accepted, !tc.wantErr)
			}
		})
	}
}

type smtpResult struct {
	authAttempted bool
	accepted      bool
	err           error
}

func serveSMTP(ctx context.Context, listener net.Listener, advertiseAuth, requireAuth bool) (result smtpResult) {
	connection, err := listener.Accept()
	if err != nil {
		result.err = err
		return result
	}
	defer func() { _ = connection.Close() }()
	go func() {
		<-ctx.Done()
		_ = connection.Close()
	}()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		result.err = err
		return result
	}
	protocol := textproto.NewConn(connection)
	if err := protocol.PrintfLine("220 localhost SMTP test server"); err != nil {
		result.err = err
		return result
	}
	var authenticated bool
	for {
		line, err := protocol.ReadLine()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				result.err = err
			}
			return result
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			result.err = errors.New("empty SMTP command")
			return result
		}
		response := "250 OK"
		switch strings.ToUpper(fields[0]) {
		case "EHLO", "HELO":
			if advertiseAuth {
				if err := protocol.PrintfLine("250-localhost"); err != nil {
					result.err = err
					return result
				}
				response = "250 AUTH PLAIN"
			}
		case "AUTH":
			result.authAttempted = true
			if len(fields) != 3 || fields[1] != "PLAIN" {
				result.err = errors.New("expected SMTP AUTH PLAIN with initial response")
				return result
			}
			payload, err := base64.StdEncoding.DecodeString(fields[2])
			parts := bytes.Split(payload, []byte{0})
			authenticated = err == nil && len(parts) == 3 && string(parts[1]) == smtpTestUser && string(parts[2]) == smtpTestPass
			response = "535 Invalid credentials"
			if authenticated {
				response = "235 Authentication succeeded"
			}
		case "MAIL":
			if requireAuth && !authenticated {
				response = "503 You must authenticate first"
			}
		case "RCPT", "RSET", "NOOP":
		case "*":
			response = "501 Authentication cancelled"
		case "DATA":
			if requireAuth && !authenticated {
				result.err = errors.New("client sent DATA without authenticating")
				return result
			}
			if err := protocol.PrintfLine("354 Send message"); err != nil {
				result.err = err
				return result
			}
			if _, err := io.Copy(io.Discard, protocol.DotReader()); err != nil {
				result.err = err
				return result
			}
			result.accepted = true
		case "QUIT":
			result.err = protocol.PrintfLine("221 Goodbye")
			return result
		default:
			result.err = fmt.Errorf("unexpected SMTP command %s", fields[0])
			return result
		}
		if err := protocol.PrintfLine("%s", response); err != nil {
			result.err = err
			return result
		}
	}
}
