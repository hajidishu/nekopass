package registration

import (
	"bytes"
	"image/png"
	"testing"
)

func TestEmailsAndCaptchaAreSafe(t *testing.T) {
	for _, input := range []string{"a\r\nBcc: other@example.test", "Name <a@example.test>", "not-email"} {
		if _, err := Email(input); err == nil {
			t.Fatal("unsafe email accepted", input)
		}
	}
	if value, err := Email(" A@EXAMPLE.TEST "); err != nil || value != "a@example.test" {
		t.Fatal(value, err)
	}
	code, err := Digits(6)
	if err != nil || len(code) != 6 {
		t.Fatal(err)
	}
	image, err := Image(code)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(image))
	if err != nil || decoded.Bounds().Dx() != 160 || decoded.Bounds().Dy() != 50 {
		t.Fatal("invalid captcha PNG", err)
	}
	cfg := SMTP{Host: "mail.example.test", Port: 587, Security: "starttls", From: "noreply@example.test"}
	if cfg.Validate(true) != nil {
		t.Fatal("valid SMTP rejected")
	}
	cfg.FromName = "name\r\nBcc: bad"
	if cfg.Validate(true) == nil {
		t.Fatal("SMTP header injection")
	}
}
