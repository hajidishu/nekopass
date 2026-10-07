package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/registration"
)

func registrationFixture(t *testing.T) (*securityFixture, *string) {
	f := newSecurityFixture(t)
	v := defaultSettings()
	v.RegistrationEnabled = true
	v.CaptchaMode = "off"
	v.SMTP = registration.SMTP{Host: "mail.example.test", Port: 2525, Security: "plain", From: "noreply@example.test"}
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	code := new(string)
	f.s.sendMail = func(_ context.Context, _ registration.SMTP, _, value, _ string) error { *code = value; return nil }
	t.Cleanup(func() {
		f.p.Exec(context.Background(), "DELETE FROM registration_codes")
		f.p.Exec(context.Background(), "DELETE FROM registration_captchas")
	})
	return f, code
}

func verification(t *testing.T, f *securityFixture, email string) string {
	t.Helper()
	w := f.request(0, "registration/email-code", "POST", map[string]string{"email": email, "captcha_id": "", "captcha": ""})
	securityStatus(t, w, 200)
	var data struct {
		ID string `json:"verification_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || !hashOK(data.ID) {
		t.Fatal("verification handle missing", err)
	}
	return data.ID
}

func TestPublicRegistrationEmailValidationAndPrivilegeIsolation(t *testing.T) {
	f, code := registrationFixture(t)
	ctx := context.Background()
	email := Secret()[:12] + "@" + strings.Repeat("a", 45) + ".example.test"
	token := verification(t, f, email)
	securityStatus(t, f.request(0, "registration/email-code", "POST", map[string]string{"email": email}), 429)
	body := map[string]string{"email": email, "password": "fixture-registration-password", "confirm_password": "fixture-registration-password", "email_code": *code, "verification_id": token, "invite_code": "does-not-exist"}
	body["confirm_password"] = "different"
	securityStatus(t, f.request(0, "register", "POST", body), 400)
	body["confirm_password"] = body["password"]
	spoof := map[string]any{}
	for k, v := range body {
		spoof[k] = v
	}
	spoof["is_admin"] = true
	securityStatus(t, f.request(0, "register", "POST", spoof), 400)
	body["email"] = "Other" + email
	securityStatus(t, f.request(0, "register", "POST", body), 400)
	body["email"] = "  " + email + "  "
	w := f.request(0, "register", "POST", body)
	securityStatus(t, w, 201)
	var id int64
	var admin, verified bool
	var inviter *int64
	var plan *int64
	if err := f.p.QueryRow(ctx, "SELECT id,is_admin,email_verified_at IS NOT NULL,inviter_id,plan_id FROM users WHERE username=$1", email).Scan(&id, &admin, &verified, &inviter, &plan); err != nil || admin || !verified || inviter != nil || plan != nil {
		t.Fatal("unsafe new account", err)
	}
	t.Cleanup(func() {
		f.p.Exec(ctx, "DELETE FROM sessions WHERE user_id=$1", id)
		f.p.Exec(ctx, "DELETE FROM users WHERE id=$1", id)
	})
	securityStatus(t, f.request(0, "register", "POST", body), 400)
	securityStatus(t, f.request(0, "login", "POST", map[string]string{"username": email, "password": body["password"]}), 200)
	securityStatus(t, f.request(0, "login", "POST", map[string]string{"username": strings.ToUpper(email), "password": body["password"]}), 200)
	v := defaultSettings()
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	securityStatus(t, f.request(0, "register", "POST", body), 403)
}

func TestRegistrationCaptchaIsOneUseAndEmailCodeAttemptsPersist(t *testing.T) {
	f, code := registrationFixture(t)
	ctx := context.Background()
	v := defaultSettings()
	v.RegistrationEnabled = true
	v.SMTP = registration.SMTP{Host: "mail.example.test", Port: 25, Security: "plain", From: "noreply@example.test"}
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	w := f.request(0, "registration/captcha", "GET", nil)
	securityStatus(t, w, 200)
	var image map[string]string
	json.Unmarshal(w.Body.Bytes(), &image)
	if !hashOK(image["id"]) || image["image"] == "" || image["answer"] != "" {
		t.Fatal("captcha image missing or answer exposed")
	}
	f.p.Exec(ctx, "UPDATE registration_captchas SET answer_hash=$2 WHERE id=$1", Hash(image["id"]), Hash(image["id"]+"123456"))
	email := Secret()[:12] + "@example.test"
	request := map[string]string{"email": email, "captcha_id": image["id"], "captcha": "123456"}
	w = f.request(0, "registration/email-code", "POST", request)
	securityStatus(t, w, 200)
	securityStatus(t, f.request(0, "registration/email-code", "POST", request), 400)
	var result struct {
		ID string `json:"verification_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	body := map[string]string{"email": email, "password": "fixture-registration-password", "confirm_password": "fixture-registration-password", "email_code": "wrong!", "verification_id": result.ID, "invite_code": ""}
	for i := 0; i < 5; i++ {
		b, _ := json.Marshal(body)
		w = f.raw(0, "register", "POST", string(b), func(r *http.Request) { r.RemoteAddr = fmt.Sprintf("198.51.100.%d:1000", i+20) })
		securityStatus(t, w, 400)
	}
	body["email_code"] = *code
	b, _ := json.Marshal(body)
	securityStatus(t, f.raw(0, "register", "POST", string(b), func(r *http.Request) { r.RemoteAddr = "198.51.100.30:1000" }), 400)
}

func TestVerifiedRegistrationIsAtomicUnderConcurrentReuse(t *testing.T) {
	f, code := registrationFixture(t)
	email := Secret()[:12] + "@example.test"
	token := verification(t, f, email)
	body := map[string]string{"email": email, "password": "fixture-registration-password", "confirm_password": "fixture-registration-password", "email_code": *code, "verification_id": token, "invite_code": ""}
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- f.request(0, "register", "POST", body).Code }()
	}
	wg.Wait()
	close(results)
	success := 0
	for result := range results {
		if result == 201 {
			success++
		} else if result != 400 && result != 409 {
			t.Fatal("unexpected result", result)
		}
	}
	if success != 1 {
		t.Fatal("code replay created extra accounts")
	}
	registeredEmail := email
	t.Cleanup(func() { f.p.Exec(context.Background(), "DELETE FROM users WHERE username=$1", registeredEmail) })
	// Expired codes are never accepted, regardless of possessing the correct code.
	email = Secret()[:12] + "@example.test"
	token = verification(t, f, email)
	f.p.Exec(context.Background(), "UPDATE registration_codes SET expires_at=$2 WHERE id=$1", Hash(token), time.Now().Add(-time.Second))
	body["email"] = email
	body["verification_id"] = token
	body["email_code"] = *code
	securityStatus(t, f.request(0, "register", "POST", body), 400)
}

func TestRegistrationBindsOnlyServerResolvedInvitationAndAdminControlsOverrides(t *testing.T) {
	f, code := registrationFixture(t)
	ctx := context.Background()
	var invite string
	if err := f.p.QueryRow(ctx, "SELECT invite_code FROM users WHERE id=$1", f.other).Scan(&invite); err != nil {
		t.Fatal(err)
	}
	email := Secret()[:12] + "@example.test"
	id := verification(t, f, email)
	securityStatus(t, f.request(0, "register", "POST", map[string]string{"email": email, "password": "fixture-registration-password", "confirm_password": "fixture-registration-password", "email_code": *code, "verification_id": id, "invite_code": invite}), 201)
	var owner, inviter int64
	if err := f.p.QueryRow(ctx, "SELECT id,inviter_id FROM users WHERE username=$1", email).Scan(&owner, &inviter); err != nil || inviter != f.other {
		t.Fatal("invitation not bound", err)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM users WHERE id=$1", owner) })
	body := UserInput{Username: Secret(), Enabled: true, PlanID: f.otherPlan, Referral: &UserReferralSettings{Mode: "recurring", Rate: new(string)}}
	*body.Referral.Rate = "25.50"
	on := true
	body.Referral.Enabled = &on
	path := "admin/users/" + formatID(f.other)
	securityStatus(t, f.request(f.user, path, "PUT", body), 403)
	securityStatus(t, f.request(f.admin, path, "PUT", body), 200)
	var mode string
	var rate int
	var enabled bool
	if err := f.p.QueryRow(ctx, "SELECT referral_enabled,referral_mode,referral_rate_bps FROM users WHERE id=$1", f.other).Scan(&enabled, &mode, &rate); err != nil || !enabled || mode != "recurring" || rate != 2550 {
		t.Fatal("override not saved", err)
	}
	// Legacy administrator requests that omit the override preserve it.
	body.Referral = nil
	securityStatus(t, f.request(f.admin, path, "PUT", body), 200)
	if err := f.p.QueryRow(ctx, "SELECT referral_rate_bps FROM users WHERE id=$1", f.other).Scan(&rate); err != nil || rate != 2550 {
		t.Fatal("omitted override erased", err)
	}
}
