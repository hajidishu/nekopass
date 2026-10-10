package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateAdministratorIdentity(t *testing.T) {
	c := DefaultConfig()
	c.AdminIDs = []int64{42}
	c.Token = "12345:" + strings.Repeat("x", 35)
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		user User
		chat Chat
		want bool
	}{{User{ID: 42}, Chat{ID: 42, Type: "private"}, true}, {User{ID: 43}, Chat{ID: 43, Type: "private"}, false}, {User{ID: 42}, Chat{ID: -100, Type: "supergroup"}, false}, {User{ID: 42}, Chat{ID: 43, Type: "private"}, false}, {User{ID: 42, IsBot: true}, Chat{ID: 42, Type: "private"}, false}} {
		if c.Allows(v.user, v.chat) != v.want {
			t.Fatal("identity boundary failed", v)
		}
	}
	c.AdminIDs = []int64{-42}
	if c.Normalize() == nil {
		t.Fatal("group ID accepted as administrator")
	}
}
func TestAPIPayloadAndCredentialSafeErrors(t *testing.T) {
	token := "12345:" + strings.Repeat("x", 35)
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Error("not POST")
		}
		json.NewDecoder(r.Body).Decode(&sent)
		if strings.HasSuffix(r.URL.Path, "sendMessage") {
			fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
		} else {
			fmt.Fprintf(w, `{"ok":false,"error_code":401,"description":%q}`, "credential "+token)
		}
	}))
	defer server.Close()
	c := NewClient(token).(*Client)
	c.baseURL = server.URL
	if err := c.Send(context.Background(), 42, "hello", nil); err != nil {
		t.Fatal(err)
	}
	if sent["protect_content"] != true || sent["parse_mode"] != "HTML" || sent["chat_id"] != float64(42) {
		t.Fatal("unsafe message payload", sent)
	}
	_, err := c.Me(context.Background())
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "credential") {
		t.Fatal("API error exposed credential")
	}
	server.Close()
	_, err = c.Me(context.Background())
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "/bot") {
		t.Fatal("transport error exposed request URL")
	}
}
func TestNoCredentialRedirect(t *testing.T) {
	var contacted bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted = true }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	c := NewClient("12345:" + strings.Repeat("x", 35)).(*Client)
	c.baseURL = server.URL
	if _, err := c.Me(context.Background()); err == nil || contacted {
		t.Fatal("redirect followed")
	}
}

func TestLargeUpdateBatchUsesBoundedFallback(t *testing.T) {
	var limits []float64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		limits = append(limits, body["limit"].(float64))
		if body["limit"] == float64(100) {
			fmt.Fprint(w, strings.Repeat("x", (2<<20)+1))
			return
		}
		fmt.Fprint(w, `{"ok":true,"result":[{"update_id":42}]}`)
	}))
	defer server.Close()
	c := NewClient("12345:" + strings.Repeat("x", 35)).(*Client)
	c.baseURL = server.URL
	updates, err := c.Updates(context.Background(), 42)
	if err != nil || len(updates) != 1 || updates[0].ID != 42 || len(limits) != 2 || limits[1] != 1 {
		t.Fatal("large batch did not recover safely", err)
	}
}
