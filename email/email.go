package email

import (
	"context"
	"fmt"
	"log"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	mail "github.com/wneessen/go-mail"
)

type Sender interface {
	SendVerification(ctx context.Context, user core.User, token string) error
	SendPasswordReset(ctx context.Context, user core.User, token string) error
	SendEmailChange(ctx context.Context, user core.User, newEmail, token string) error
}

type Mailer struct {
	cfg config.Mail
}

func NewMailer(cfg config.Mail) *Mailer {
	return &Mailer{cfg: cfg}
}

func (m *Mailer) SendVerification(ctx context.Context, user core.User, token string) error {
	subject := "Verify your email"
	body := fmt.Sprintf("Hello %s,\n\nUse the following token to verify your email: %s\n", user.Username, token)
	return m.send(ctx, user.Email, subject, body)
}

func (m *Mailer) SendPasswordReset(ctx context.Context, user core.User, token string) error {
	subject := "Reset your password"
	body := fmt.Sprintf("Hello %s,\n\nUse the following token to reset your password: %s\n", user.Username, token)
	return m.send(ctx, user.Email, subject, body)
}

func (m *Mailer) SendEmailChange(ctx context.Context, user core.User, newEmail, token string) error {
	// Notify old email (Best Effort) to prevent silent account takeover
	notifySubject := "Security Alert: Email Change Requested"
	notifyBody := fmt.Sprintf("Hello %s,\n\nA request to change your email to %s has been initiated.\nIf this was you, you can ignore this message.\nIf you did not request this change, please contact support immediately.\n", user.Username, newEmail)

	if err := m.send(ctx, user.Email, notifySubject, notifyBody); err != nil {
		log.Printf("failed to send email change notification to old email %s: %v", user.Email, err)
	}

	subject := "Confirm your new email"
	body := fmt.Sprintf("Hello %s,\n\nConfirm the email change to %s with token: %s\n", user.Username, newEmail, token)
	return m.send(ctx, newEmail, subject, body)
}

func (m *Mailer) send(ctx context.Context, recipient, subject, body string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.fromAddress()); err != nil {
		return err
	}
	if err := msg.AddTo(recipient); err != nil {
		return err
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextPlain, body)

	opts := []mail.Option{
		mail.WithPort(m.cfg.Port),
		mail.WithUsername(m.cfg.User),
		mail.WithPassword(m.cfg.Pass),
		mail.WithTLSPolicy(m.tlsPolicy()),
	}
	if m.cfg.UseSSL {
		opts = append(opts, mail.WithSSL())
	}
	client, err := mail.NewClient(m.cfg.Host, opts...)
	if err != nil {
		return err
	}

	return client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) fromAddress() string {
	if m.cfg.From != "" {
		return m.cfg.From
	}
	return m.cfg.User
}

func (m *Mailer) tlsPolicy() mail.TLSPolicy {
	if m.cfg.UseSSL {
		return mail.TLSMandatory
	}
	return mail.TLSOpportunistic
}

type NopSender struct{}

func (NopSender) SendVerification(ctx context.Context, user core.User, token string) error {
	return nil
}
func (NopSender) SendPasswordReset(ctx context.Context, user core.User, token string) error {
	return nil
}
func (NopSender) SendEmailChange(ctx context.Context, user core.User, newEmail, token string) error {
	return nil
}
