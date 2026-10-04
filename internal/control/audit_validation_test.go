package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResourceIDsCannotTurnUpdatesIntoCreates(t *testing.T) {
	for _, raw := range []string{"", "garbage", "0", "-1", "9223372036854775808"} {
		r := httptest.NewRequest(http.MethodPut, "/", nil)
		r.SetPathValue("id", raw)
		w := httptest.NewRecorder()
		if _, ok := resourceID(w, r); ok || w.Code != 400 {
			t.Fatalf("invalid update ID accepted: %q", raw)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := httptest.NewRequest(method, "/", nil)
		r.SetPathValue("id", "12")
		if id, ok := resourceID(httptest.NewRecorder(), r); !ok || id != 12 {
			t.Fatal("valid resource ID rejected")
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if id, ok := resourceID(httptest.NewRecorder(), r); !ok || id != 0 {
		t.Fatal("collection creation rejected")
	}
}

func TestDecodeRequiresOneJSONObject(t *testing.T) {
	for _, body := range []string{"null", "[]", "42", "true", "\"value\"", "{} {}", "{\"unexpected\":1}"} {
		in := struct {
			Name string `json:"name"`
		}{Name: "preserve"}
		w := httptest.NewRecorder()
		if decode(w, httptest.NewRequest("POST", "/", strings.NewReader(body)), &in) || w.Code != 400 {
			t.Fatalf("invalid JSON accepted: %s", body)
		}
		if in.Name != "preserve" {
			t.Fatal("rejected request mutated defaults")
		}
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(" \n{\"name\":\"valid\"}\r\n")), &in) || in.Name != "valid" {
		t.Fatal("valid object rejected")
	}
}
