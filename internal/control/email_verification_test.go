package control

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nekopass/nekopass/internal/registration"
)

func TestRegistrationWithoutEmailVerificationDoesNotRequireSMTPOrMarkVerified(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	v := defaultSettings()
	v.RegistrationEnabled = true
	v.CaptchaMode = "off"
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 400)
	v.RegistrationEmailVerification = false
	securityStatus(t, f.request(f.user, "admin/settings", "PUT", v), 403)
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	sends := 0
	f.s.sendMail = func(context.Context, registration.SMTP, string, string, string) error { sends++; return nil }
	w := f.request(0, "registration", "GET", nil)
	var info struct {
		Required bool `json:"email_verification"`
	}
	json.Unmarshal(w.Body.Bytes(), &info)
	if info.Required {
		t.Fatal("verification flag not public")
	}
	securityStatus(t, f.request(0, "registration/email-code", "POST", map[string]string{"email": "unused@example.test"}), 403)
	email := Secret()[:12] + "@example.test"
	body := map[string]string{"email": email, "password": "fixture-direct-password", "confirm_password": "fixture-direct-password"}
	securityStatus(t, f.request(0, "register", "POST", body), 201)
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM users WHERE username=$1", email) })
	var verified, admin bool
	if err := f.p.QueryRow(ctx, "SELECT email_verified_at IS NOT NULL,is_admin FROM users WHERE username=$1", email).Scan(&verified, &admin); err != nil || verified || admin {
		t.Fatal("unverified account marked verified/admin", err)
	}
	securityStatus(t, f.request(0, "register", "POST", body), 409)
	if sends != 0 {
		t.Fatal("disabled verification sent email")
	}
	v.RegistrationEmailVerification = true
	v.SMTP = registration.SMTP{Host: "mail.example.test", Port: 25, Security: "plain", From: "noreply@example.test"}
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	body["email"] = Secret()[:12] + "@example.test"
	securityStatus(t, f.request(0, "register", "POST", body), 400)
	// Old persisted settings do not silently turn verification off on upgrade.
	f.p.Exec(ctx, "UPDATE site_settings SET config=config-'registration_email_verification' WHERE id=1")
	settings, err := f.s.readSettings(ctx)
	if err != nil || !settings.RegistrationEmailVerification {
		t.Fatal("legacy settings lost email requirement", err)
	}
}

func TestRegistrationWithoutEmailVerificationStillChecksCaptchaAndInvitation(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	v := defaultSettings()
	v.RegistrationEnabled = true
	v.RegistrationEmailVerification = false
	v.ReferralEnabled = true
	v.ForceInvite = true
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	var invite string
	f.p.QueryRow(ctx, "SELECT invite_code FROM users WHERE id=$1", f.other).Scan(&invite)
	email := Secret()[:12] + "@example.test"
	body := map[string]string{"email": email, "password": "fixture-direct-password", "confirm_password": "fixture-direct-password", "invite_code": invite}
	securityStatus(t, f.request(0, "register", "POST", body), 400)
	mint := func() string {
		t.Helper()
		w := f.request(0, "registration/captcha", "GET", nil)
		securityStatus(t, w, 200)
		var c struct {
			ID string `json:"id"`
		}
		json.Unmarshal(w.Body.Bytes(), &c)
		if !hashOK(c.ID) {
			t.Fatal("captcha unavailable")
		}
		f.p.Exec(ctx, "UPDATE registration_captchas SET answer_hash=$2 WHERE id=$1", Hash(c.ID), Hash(c.ID+"123456"))
		t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM registration_captchas WHERE id=$1", Hash(c.ID)) })
		return c.ID
	}
	body["captcha_id"] = mint()
	body["captcha"] = "123456"
	body["invite_code"] = "missing-code"
	securityStatus(t, f.request(0, "register", "POST", body), 400)
	body["captcha_id"] = mint()
	body["invite_code"] = invite
	securityStatus(t, f.request(0, "register", "POST", body), 201)
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM users WHERE username=$1", email) })
	var inviter int64
	var verified bool
	if err := f.p.QueryRow(ctx, "SELECT inviter_id,email_verified_at IS NOT NULL FROM users WHERE username=$1", email).Scan(&inviter, &verified); err != nil || inviter != f.other || verified {
		t.Fatal("invitation/verification state incorrect", err)
	}
	body["email"] = Secret()[:12] + "@example.test"
	securityStatus(t, f.request(0, "register", "POST", body), 400)
	v.RegistrationEnabled = false
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	securityStatus(t, f.request(0, "register", "POST", body), 403)
}
