package email

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
)

// MockSMTPServer is a simple TCP server that mimics SMTP to capture sent emails.
func startMockSMTPServer(t *testing.T, recipients chan<- string) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock smtp: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSMTPConnection(conn, recipients)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return fmt.Sprintf("127.0.0.1:%d", addr.Port), func() { _ = ln.Close() }
}

func handleSMTPConnection(conn net.Conn, recipients chan<- string) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Initial greeting
	_, _ = writer.WriteString("220 mock.smtp ESMTP\r\n")
	_ = writer.Flush()

	inData := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		if inData {
			if line == "." {
				inData = false
				_, _ = writer.WriteString("250 OK\r\n")
				_ = writer.Flush()
			}
			// Ignore data lines
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			_, _ = writer.WriteString("250-Hello\r\n250 AUTH PLAIN LOGIN\r\n")
		case strings.HasPrefix(upper, "AUTH"):
			_, _ = writer.WriteString("235 Authentication successful\r\n")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			_, _ = writer.WriteString("250 OK\r\n")
		case strings.HasPrefix(upper, "RCPT TO:"):
			// Capture recipient
			// Format: RCPT TO:<email>
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				email := strings.Trim(parts[1], "<> ")
				recipients <- email
			}
			_, _ = writer.WriteString("250 OK\r\n")
		case upper == "DATA":
			inData = true
			_, _ = writer.WriteString("354 End data with <CR><LF>.<CR><LF>\r\n")
		case upper == "QUIT":
			_, _ = writer.WriteString("221 Bye\r\n")
			_ = writer.Flush()
			return
		default:
			// Just say OK for anything else (NOOP, RSET, etc)
			_, _ = writer.WriteString("250 OK\r\n")
		}
		_ = writer.Flush()
	}
}

func TestSendEmailChange_SecurityNotification(t *testing.T) {
	recipients := make(chan string, 10)
	addr, cleanup := startMockSMTPServer(t, recipients)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	cfg := config.Mail{
		Host:   host,
		Port:   port,
		User:   "test",
		Pass:   "test",
		From:   "admin@example.com",
		UseSSL: false, // Use plain text for mock
	}
	mailer := NewMailer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user := core.User{
		Username: "Alice",
		Email:    "alice@old.com",
	}
	newEmail := "alice@new.com"

	err := mailer.SendEmailChange(ctx, user, newEmail, "token123")
	if err != nil {
		t.Fatalf("SendEmailChange failed: %v", err)
	}

	// Collect received emails
	received := make([]string, 0)
	timeout := time.After(1 * time.Second)
loop:
	for {
		select {
		case r := <-recipients:
			received = append(received, r)
		case <-timeout:
			break loop
		}
	}

	// Verify we ONLY received email to newEmail (Reproduction of issue)
	// Once fixed, we expect this to contain user.Email as well.
	foundNew := false
	foundOld := false

	for _, r := range received {
		if r == newEmail {
			foundNew = true
		}
		if r == user.Email {
			foundOld = true
		}
	}

	if !foundNew {
		t.Error("Expected email to be sent to new email address")
	}

	if !foundOld {
		t.Errorf("SECURITY GAP: No notification sent to old email address %s. Account takeover risk!", user.Email)
	}
}
