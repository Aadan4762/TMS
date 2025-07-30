package utils

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/wneessen/go-mail"
)

func SendOTPEmail(email, firstName, code, purpose string) {
	config := getEmailConfig()

	message := mail.NewMsg()
	if err := message.From(config.SMTPUsername); err != nil {
		fmt.Printf("Failed to set From address: %v\n", err)
		return
	}
	if err := message.To(email); err != nil {
		fmt.Printf("Failed to set To address: %v\n", err)
		return
	}

	var subject string
	switch purpose {
	case "registration":
		subject = "Email Verification - Ministry of Education"
	case "login":
		subject = "Login Verification Code - Ministry of Education"
	case "reset_password":
		subject = "Password Reset Code - Ministry of Education"
	default:
		subject = "Verification Code - Ministry of Education"
	}

	message.Subject(subject)

	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{.Subject}}</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f9f9f9; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 20px auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        .header { text-align: center; margin-bottom: 20px; }
        .logo { background-color: #1e3a8a; color: white; padding: 10px 20px; border-radius: 4px; display: inline-block; font-weight: bold; }
        h1 { color: #1e3a8a; margin: 20px 0 10px; }
        .code { background-color: #e0f2fe; padding: 20px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 24px; font-weight: bold; text-align: center; margin: 20px 0; color: #1e3a8a; border: 2px dashed #1e3a8a; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">Ministry of Education - Kenya</div>
        </div>
        <h1>{{.Title}}</h1>
        <p>Dear {{.FirstName}},</p>
        <p>{{.Message}}</p>
        <div class="code">{{.Code}}</div>
        <p><strong>Important:</strong> This code will expire in 5 minutes.</p>
        <div class="footer">
            <p><strong>Ministry of Education ICT Department</strong><br>
            Government of Kenya</p>
        </div>
    </div>
</body>
</html>`

	var title, messageText string
	switch purpose {
	case "registration":
		title = "Email Verification Required"
		messageText = "Please use the verification code below to complete your registration:"
	case "login":
		title = "Login Verification"
		messageText = "Use this code to complete your login:"
	case "reset_password":
		title = "Password Reset"
		messageText = "Use this code to reset your password:"
	}

	data := struct {
		Subject   string
		Title     string
		FirstName string
		Message   string
		Code      string
	}{
		Subject:   subject,
		Title:     title,
		FirstName: firstName,
		Message:   messageText,
		Code:      code,
	}

	tmpl, err := template.New("email").Parse(htmlTemplate)
	if err != nil {
		fmt.Printf("Failed to parse template: %v\n", err)
		return
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		fmt.Printf("Failed to execute template: %v\n", err)
		return
	}

	message.SetBodyString(mail.TypeTextHTML, body.String())

	client, err := mail.NewClient(config.SMTPHost,
		mail.WithPort(config.SMTPPort),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(config.SMTPUsername),
		mail.WithPassword(config.SMTPPassword),
		mail.WithTLSPolicy(mail.TLSMandatory))

	if err != nil {
		fmt.Printf("Failed to create email client: %v\n", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.DialWithContext(ctx); err != nil {
		fmt.Printf("Failed to connect to SMTP: %v\n", err)
		return
	}
	defer client.Close()

	if err := client.Send(message); err != nil {
		fmt.Printf("Failed to send email: %v\n", err)
		return
	}

	fmt.Printf("Email sent successfully to %s\n", email)
}

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
}

// getEmailConfig reads email configuration from environment variables
func getEmailConfig() EmailConfig {
	// Get SMTP host (with fallback)
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "smtp.gmail.com" // fallback to Gmail SMTP
		log.Println("SMTP_HOST not set, using default:", smtpHost)
	}

	// Get SMTP port (with fallback)
	smtpPortStr := os.Getenv("SMTP_PORT")
	smtpPort := 587 // default port
	if smtpPortStr != "" {
		if port, err := strconv.Atoi(smtpPortStr); err == nil {
			smtpPort = port
		} else {
			log.Printf("Invalid SMTP_PORT value: %s, using default: %d\n", smtpPortStr, smtpPort)
		}
	} else {
		log.Printf("SMTP_PORT not set, using default: %d\n", smtpPort)
	}

	// Get SMTP username
	smtpUsername := os.Getenv("SMTP_USERNAME")
	if smtpUsername == "" {
		// Fallback to EMAIL_FROM if SMTP_USERNAME is not set
		smtpUsername = os.Getenv("EMAIL_FROM")
		if smtpUsername == "" {
			log.Fatal("Both SMTP_USERNAME and EMAIL_FROM are not set in environment variables")
		}
		log.Println("SMTP_USERNAME not set, using EMAIL_FROM:", smtpUsername)
	}

	// Get SMTP password
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	if smtpPassword == "" {
		log.Fatal("SMTP_PASSWORD not set in environment variables")
	}

	return EmailConfig{
		SMTPHost:     smtpHost,
		SMTPPort:     smtpPort,
		SMTPUsername: smtpUsername,
		SMTPPassword: smtpPassword,
	}
}
