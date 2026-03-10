package mailer

import (
	"fmt"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/config"
	"gopkg.in/gomail.v2"
)

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

type Mailer struct {
	config *config.SMTPConfig
	dialer *gomail.Dialer
}

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

func (m *Mailer) Send(email Email) error {
	if len(email.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	msg := gomail.NewMessage()
	m.setEmailMessage(msg, email)

	return m.dialer.DialAndSend(msg)
}

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

func (m *Mailer) SendSimple(to []string, subject, body string) error {
	return m.Send(Email{
		To:      to,
		Subject: subject,
		Body:    body,
	})
}

func (m *Mailer) SendHTML(to []string, subject, htmlBody string) error {
	return m.Send(Email{
		To:       to,
		Subject:  subject,
		HTMLBody: htmlBody,
	})
}

func (m *Mailer) SendWithAttachment(to []string, subject, body string, attachments []string) error {
	return m.Send(Email{
		To:          to,
		Subject:     subject,
		Body:        body,
		Attachments: attachments,
	})
}

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
