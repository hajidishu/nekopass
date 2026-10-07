package registration

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type SMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"` // starttls, tls, plain (explicitly selected)
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	FromName string `json:"from_name"`
}

func Email(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	a, err := mail.ParseAddress(value)
	if err != nil || a.Address != value || len(value) > 254 || !strings.Contains(value, "@") || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("请输入有效的电子邮件地址")
	}
	return value, nil
}

func (s SMTP) Validate(required bool) error {
	if !required && s.Host == "" {
		return nil
	}
	if s.Host == "" || strings.ContainsAny(s.Host, "/\r\n\x00 \t") || s.Port < 1 || s.Port > 65535 || (s.Security != "starttls" && s.Security != "tls" && s.Security != "plain") {
		return errors.New("SMTP 主机、端口或连接方式无效")
	}
	if _, err := Email(s.From); err != nil {
		return errors.New("SMTP 发件地址无效")
	}
	if strings.ContainsAny(s.FromName+s.Username, "\r\n\x00") || len(s.FromName) > 200 || len(s.Username) > 254 || len(s.Password) > 1024 {
		return errors.New("SMTP 配置无效")
	}
	return nil
}

// SendCode verifies certificates, requires STARTTLS when selected, and bounds
// the entire SMTP conversation. Errors never include credentials or responses.
func SendCode(ctx context.Context, cfg SMTP, to, code, site string) error {
	if err := cfg.Validate(true); err != nil {
		return err
	}
	addressTo, err := Email(to)
	if err != nil || len(code) != 6 || strings.Trim(code, "0123456789") != "" || strings.ContainsAny(site, "\r\n\x00") {
		return errors.New("邮件参数无效")
	}
	to = addressTo
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 10 * time.Second}
	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	var c net.Conn
	tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if cfg.Security == "tls" {
		c, err = (&tls.Dialer{NetDialer: &d, Config: tlsConfig}).DialContext(ctx, "tcp", address)
	} else {
		c, err = d.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return errors.New("邮件服务器连接失败")
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	client, err := smtp.NewClient(c, cfg.Host)
	if err != nil {
		return errors.New("邮件服务器握手失败")
	}
	defer client.Close()
	if cfg.Security == "starttls" {
		if err = client.StartTLS(tlsConfig); err != nil {
			return errors.New("邮件服务器 STARTTLS 失败")
		}
	}
	if cfg.Username != "" {
		// PlainAuth only permits clear transport to localhost. Administrators
		// selecting a plain remote relay can send without SMTP authentication.
		if err = client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return errors.New("邮件服务器认证失败")
		}
	}
	if err = client.Mail(cfg.From); err != nil {
		return errors.New("邮件发送失败")
	}
	if err = client.Rcpt(to); err != nil {
		return errors.New("邮件发送失败")
	}
	w, err := client.Data()
	if err != nil {
		return errors.New("邮件发送失败")
	}
	from := (&mail.Address{Name: cfg.FromName, Address: cfg.From}).String()
	subject := mime.QEncoding.Encode("UTF-8", site+" 注册验证码")
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n您的注册验证码是：%s\r\n验证码 10 分钟内有效。如非本人操作，请忽略此邮件。\r\n", from, to, subject, code)
	if _, err = w.Write([]byte(message)); err != nil {
		return errors.New("邮件发送失败")
	}
	if err = w.Close(); err != nil {
		return errors.New("邮件发送失败")
	}
	// DATA acknowledgement means accepted; a later QUIT failure must not
	// invalidate a code whose message was already handed to the SMTP server.
	_ = client.Quit()
	return nil
}
