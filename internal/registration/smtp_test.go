package registration

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func smtpFixture(t *testing.T) (SMTP, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	transcript := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		w := bufio.NewWriter(c)
		write := func(line string) { w.WriteString(line + "\r\n"); w.Flush() }
		write("220 localhost fixture")
		var body strings.Builder
		data := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if data {
				if line == "." {
					data = false
					transcript <- body.String()
					write("250 accepted")
				} else {
					body.WriteString(line + "\n")
				}
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				write("250 localhost")
			case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
				write("250 ok")
			case line == "DATA":
				data = true
				write("354 send body")
			case line == "QUIT":
				write("221 bye")
				return
			default:
				write("502 unsupported")
			}
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return SMTP{Host: "127.0.0.1", Port: port, Security: "plain", From: "noreply@example.test", FromName: "测试"}, transcript
}

func TestSMTPConversationDeliversCodeAndRequiresChosenTLS(t *testing.T) {
	cfg, received := smtpFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := SendCode(ctx, cfg, "user@example.test", "123456", "Nekopass"); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-received:
		if !strings.Contains(message, "123456") || !strings.Contains(message, "To: user@example.test") || !strings.Contains(message, "Content-Type: text/plain; charset=UTF-8") {
			t.Fatal("mail content invalid")
		}
	case <-ctx.Done():
		t.Fatal("SMTP accepted no message")
	}
	cfg, _ = smtpFixture(t)
	cfg.Security = "starttls"
	if err := SendCode(ctx, cfg, "user@example.test", "123456", "Nekopass"); err == nil {
		t.Fatal("STARTTLS silently downgraded")
	}
	// No attempt to connect for malformed values, so headers cannot be injected.
	cfg.Port, _ = strconv.Atoi("25")
	if err := SendCode(ctx, cfg, "user@example.test\r\nBcc: other@example.test", "123456", "Nekopass"); err == nil {
		t.Fatal("recipient injection accepted")
	}
}
