package control

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
)

func TestTicketsArePrivateAndRepliesSerializeWithClosing(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	v := defaultSettings()
	v.CaptchaMode = "off"
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	w := f.request(f.user, "tickets", "POST", map[string]string{"title": "连接问题", "content": "<script>fixture()</script>\n纯文本", "priority": "high"})
	securityStatus(t, w, 201)
	var created struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	id := created.ID
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM tickets WHERE id=$1", id) })
	path := "tickets/" + formatID(id)
	securityStatus(t, f.request(f.other, path, "GET", nil), 404)
	securityStatus(t, f.request(f.other, path+"/messages", "POST", map[string]string{"content": "unauthorized"}), 404)
	securityStatus(t, f.request(f.other, path+"/status", "PUT", map[string]string{"status": "closed"}), 404)
	securityStatus(t, f.request(f.user, "admin/"+path, "GET", nil), 403)
	securityStatus(t, f.request(f.admin, path, "GET", nil), 404)
	securityStatus(t, f.request(f.user, path+"/messages", "POST", map[string]any{"content": "reply", "sender_is_staff": true}), 400)
	securityStatus(t, f.request(f.admin, "admin/"+path+"/messages", "POST", map[string]string{"content": "客服回复"}), 200)
	var status string
	f.p.QueryRow(ctx, "SELECT status FROM tickets WHERE id=$1", id).Scan(&status)
	if status != "waiting_user" {
		t.Fatal("staff status not applied")
	}
	securityStatus(t, f.request(f.user, path+"/messages", "POST", map[string]string{"content": "用户回复"}), 200)
	f.p.QueryRow(ctx, "SELECT status FROM tickets WHERE id=$1", id).Scan(&status)
	if status != "waiting_staff" {
		t.Fatal("user status not applied")
	}
	var wg sync.WaitGroup
	responses := make(chan int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		responses <- f.request(f.user, path+"/status", "PUT", map[string]string{"status": "closed"}).Code
	}()
	go func() {
		defer wg.Done()
		responses <- f.request(f.admin, "admin/"+path+"/messages", "POST", map[string]string{"content": "并发回复"}).Code
	}()
	wg.Wait()
	close(responses)
	for code := range responses {
		if code != 200 && code != 409 {
			t.Fatal("invalid concurrent result", code)
		}
	}
	f.p.QueryRow(ctx, "SELECT status FROM tickets WHERE id=$1", id).Scan(&status)
	if status != "closed" {
		t.Fatal("reply reopened closed ticket")
	}
	securityStatus(t, f.request(f.user, path+"/messages", "POST", map[string]string{"content": "closed reply"}), 409)
	securityStatus(t, f.request(f.user, path+"/status", "PUT", map[string]string{"status": "open"}), 200)
	w = f.request(f.user, path, "GET", nil)
	securityStatus(t, w, 200)
	var details struct {
		Messages []struct {
			Staff   bool   `json:"sender_is_staff"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	json.Unmarshal(w.Body.Bytes(), &details)
	if len(details.Messages) < 3 || details.Messages[0].Staff || details.Messages[0].Content != "<script>fixture()</script>\n纯文本" || !details.Messages[1].Staff {
		t.Fatal("message authorship/text corrupted")
	}
	for _, actor := range []int64{f.user, f.other} {
		w = f.request(actor, "tickets", "GET", nil)
		var list struct {
			Total int `json:"total"`
		}
		json.Unmarshal(w.Body.Bytes(), &list)
		expected := 0
		if actor == f.user {
			expected = 1
		}
		if list.Total != expected {
			t.Fatal("other user tickets leaked")
		}
	}
}

func TestTicketCaptchaWorksWithRegistrationDisabledAndIsScoped(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	v := defaultSettings()
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	securityStatus(t, f.request(0, "tickets/captcha", "GET", nil), 401)
	securityStatus(t, f.request(0, "registration/captcha", "GET", nil), 403)
	mint := func(actor int64) string {
		t.Helper()
		w := f.request(actor, "tickets/captcha", "GET", nil)
		securityStatus(t, w, 200)
		var c struct {
			ID string `json:"id"`
		}
		json.Unmarshal(w.Body.Bytes(), &c)
		if !hashOK(c.ID) {
			t.Fatal("captcha missing")
		}
		f.p.Exec(ctx, "UPDATE registration_captchas SET answer_hash=$2 WHERE id=$1", Hash(c.ID), Hash(c.ID+"123456"))
		return c.ID
	}
	other := mint(f.other)
	own := mint(f.user)
	registerToken := Secret()
	f.p.Exec(ctx, "INSERT INTO registration_captchas(id,answer_hash,remote_key,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')", Hash(registerToken), Hash(registerToken+"123456"), Hash("198.51.100.10"))
	input := map[string]string{"title": "验证码工单", "content": "问题", "priority": "medium", "captcha": "123456", "captcha_id": registerToken}
	securityStatus(t, f.request(f.user, "tickets", "POST", input), 400)
	input["captcha_id"] = other
	securityStatus(t, f.request(f.user, "tickets", "POST", input), 400)
	input["captcha_id"] = own
	w := f.request(f.user, "tickets", "POST", input)
	securityStatus(t, w, 201)
	var value struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &value)
	t.Cleanup(func() {
		f.p.Exec(ctx, "DELETE FROM tickets WHERE id=$1", value.ID)
		f.p.Exec(ctx, "DELETE FROM registration_captchas WHERE id=ANY($1)", []string{Hash(other), Hash(own), Hash(registerToken)})
	})
	var exists bool
	f.p.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM registration_captchas WHERE id=$1)", Hash(own)).Scan(&exists)
	if exists {
		t.Fatal("captcha was not consumed")
	}
	if result := f.request(f.user, "tickets", "POST", input).Code; result != 400 && result != 429 {
		t.Fatal("captcha replay accepted", result)
	}
	securityStatus(t, f.request(f.user, "tickets", "POST", map[string]string{"title": "bad", "content": "bad", "priority": "urgent"}), 400)
	securityStatus(t, f.request(f.user, "tickets", "POST", map[string]any{"title": "bad", "content": "bad", "priority": "low", "user_id": f.other}), 400)
}
