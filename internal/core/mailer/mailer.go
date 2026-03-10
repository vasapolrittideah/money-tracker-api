package mailer

import (
	"fmt"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/config"
	"gopkg.in/gomail.v2"
)

// Email holds all the fields needed to compose and send an email message.
// Either Body or HTMLBody must be set. If both are provided, HTMLBody is used
// as the primary content and Body is added as a plain-text alternative.
type Email struct {
	To          []string
	Cc          []string
	Bcc         []string
	Subject     string
	Body        string
	HTMLBody    string
	Attachments []string
	Embeds      []string
}

// Mailer wraps gomail.Dialer and provides higher-level methods for sending emails
// via SMTP. It is configured once at startup and reused across the application.
type Mailer struct {
	config *config.SMTPConfig
	dialer *gomail.Dialer
}

// NewMailer creates a new Mailer using the given SMTP configuration.
// It establishes the dialer with SSL enabled (port 465).
func NewMailer(cfg *config.SMTPConfig) *Mailer {
	dialer := gomail.NewDialer(
		cfg.Host,
		cfg.Port,
		cfg.Username,
		cfg.Password,
	)
	dialer.SSL = true

	return &Mailer{config: cfg, dialer: dialer}
}

// Send opens a new SMTP connection, sends a single email, and closes the connection.
// Returns an error if To is empty or if the SMTP transaction fails.
func (m *Mailer) Send(email Email) error {
	if len(email.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	msg := gomail.NewMessage()
	m.setEmailMessage(msg, email)

	return m.dialer.DialAndSend(msg)
}

// SendBulk sends multiple emails over a single persistent SMTP connection,
// which is more efficient than calling Send repeatedly. The connection is closed
// after all emails are sent or on the first failure.
func (m *Mailer) SendBulk(emails []Email) error {
	sender, err := m.dialer.Dial()
	if err != nil {
		return err
	}
	defer sender.Close()

	for i, email := range emails {
		msg := gomail.NewMessage()
		m.setEmailMessage(msg, email)

		if err := gomail.Send(sender, msg); err != nil {
			return fmt.Errorf("failed to send email %d: %w", i+1, err)
		}

		msg.Reset()
	}

	return nil
}

// SendSimple is a convenience wrapper around Send for plain-text emails.
func (m *Mailer) SendSimple(to []string, subject, body string) error {
	return m.Send(Email{
		To:      to,
		Subject: subject,
		Body:    body,
	})
}

// SendHTML is a convenience wrapper around Send for HTML-only emails.
func (m *Mailer) SendHTML(to []string, subject, htmlBody string) error {
	return m.Send(Email{
		To:       to,
		Subject:  subject,
		HTMLBody: htmlBody,
	})
}

// SendWithAttachment is a convenience wrapper around Send for plain-text emails
// with one or more file attachments.
func (m *Mailer) SendWithAttachment(to []string, subject, body string, attachments []string) error {
	return m.Send(Email{
		To:          to,
		Subject:     subject,
		Body:        body,
		Attachments: attachments,
	})
}

// setEmailMessage populates a gomail.Message with the fields from an Email struct,
// including headers, body content, attachments, and embedded images.
func (m *Mailer) setEmailMessage(msg *gomail.Message, email Email) {
	// Set headers
	msg.SetHeader("From", m.config.From)
	msg.SetHeader("To", email.To...)

	if len(email.Cc) > 0 {
		msg.SetHeader("Cc", email.Cc...)
	}

	if len(email.Bcc) > 0 {
		msg.SetHeader("Bcc", email.Bcc...)
	}

	msg.SetHeader("Subject", email.Subject)

	// Set body
	if email.HTMLBody != "" {
		msg.SetBody("text/html", email.HTMLBody)
		if email.Body != "" {
			msg.AddAlternative("text/plain", email.Body)
		}
	} else {
		msg.SetBody("text/plain", email.Body)
	}

	// Add attachments
	for _, attachment := range email.Attachments {
		msg.Attach(attachment)
	}

	// Add embedded images
	for _, embed := range email.Embeds {
		msg.Embed(embed)
	}
}
