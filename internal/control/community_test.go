package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestForceInviteDependencyAndRegistrationWithoutServerTermsCheck(t *testing.T) {
	f, code := registrationFixture(t)
	ctx := context.Background()
	settings, err := f.s.readSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	email := Secret()[:12] + "@example.test"
	token := verification(t, f, email)
	settings.ForceInvite = true
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", settings), 400)
	settings.ReferralEnabled = true
	settings.TermsURL = "https://example.test/terms#article"
	settings.PrivacyURL = "https://example.test/privacy"
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", settings), 200)
	securityStatus(t, f.request(0, "registration/email-code", "POST", map[string]string{"email": email, "invite_code": ""}), 400)
	body := map[string]string{"email": email, "password": "fixture-community-password", "confirm_password": "fixture-community-password", "verification_id": token, "email_code": *code, "invite_code": "unknown-code"}
	securityStatus(t, f.request(0, "register", "POST", body), 400)
	var invite string
	f.p.QueryRow(ctx, "SELECT invite_code FROM users WHERE id=$1", f.other).Scan(&invite)
	body["invite_code"] = invite
	// Terms are deliberately enforced only by the frontend, as requested.
	securityStatus(t, f.request(0, "register", "POST", body), 201)
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM users WHERE username=$1", email) })
	settings.ReferralEnabled = false
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", settings), 400)
	settings.ForceInvite = false
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", settings), 200)
	for _, raw := range []string{"javascript:alert(1)", "data:text/html,hello", "https://user:password@example.test/"} {
		invalid := settings
		invalid.TermsURL = raw
		securityStatus(t, f.request(f.admin, "admin/settings", "PUT", invalid), 400)
	}
}

func TestMultipleAnnouncementsPublicationScopeAndFullText(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	ids := []int64{}
	t.Cleanup(func() {
		for _, id := range ids {
			f.p.Exec(ctx, "DELETE FROM announcements WHERE id=$1", id)
		}
	})
	create := func(title, text string, published bool, sort int) int64 {
		t.Helper()
		w := f.request(f.admin, "admin/announcements", "POST", map[string]any{"title": title, "content": text, "published": published, "sort_order": sort})
		securityStatus(t, w, 200)
		var d struct {
			ID int64 `json:"id"`
		}
		json.Unmarshal(w.Body.Bytes(), &d)
		ids = append(ids, d.ID)
		return d.ID
	}
	long := strings.Repeat("公告正文", 400)
	first := create("长公告", long, true, -100)
	hidden := create("未发布", "private draft", false, -200)
	second := create("第二条", "简短公告", true, -50)
	w := f.request(f.user, "announcements", "GET", nil)
	securityStatus(t, w, 200)
	var data struct {
		Items []struct {
			ID        int64  `json:"id"`
			Content   string `json:"content"`
			Truncated bool   `json:"truncated"`
		} `json:"items"`
	}
	json.Unmarshal(w.Body.Bytes(), &data)
	if len(data.Items) < 2 || data.Items[0].ID != first || data.Items[1].ID != second || !data.Items[0].Truncated || len([]rune(data.Items[0].Content)) != 240 {
		t.Fatal("notice sort/preview wrong")
	}
	for _, item := range data.Items {
		if item.ID == hidden {
			t.Fatal("draft exposed")
		}
	}
	securityStatus(t, f.request(f.user, "announcements/"+formatID(hidden), "GET", nil), 404)
	w = f.request(f.user, "announcements/"+formatID(first), "GET", nil)
	securityStatus(t, w, 200)
	var full struct {
		Content string `json:"content"`
	}
	json.Unmarshal(w.Body.Bytes(), &full)
	if full.Content != long {
		t.Fatal("full notice truncated")
	}
	securityStatus(t, f.request(f.user, "admin/announcements", "GET", nil), 403)
	securityStatus(t, f.request(f.user, "admin/announcements/"+formatID(first), "PUT", map[string]any{"title": "hijack", "content": "hijack", "published": true}), 403)
	securityStatus(t, f.request(f.admin, "admin/announcements/"+formatID(second), "DELETE", nil), 200)
	securityStatus(t, f.request(f.user, "announcements/"+formatID(second), "GET", nil), 404)
}
