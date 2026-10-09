package control

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestLoginFullBucketStorageAdmitsNewSource(t *testing.T) {
	s := New(nil)
	now := time.Now()
	s.loginPruned = now
	for _, group := range []string{"ip:", "account:"} {
		burst := 5
		if group == "account:" {
			burst = 10
		}
		for slot := 0; slot < maxLoginBuckets/2; slot++ {
			s.loginBuckets[fmt.Sprintf("%s%d", group, slot)] = &loginBucket{limiter: rate.NewLimiter(rate.Every(12*time.Second), burst), seen: now}
		}
	}
	for range cap(s.loginWorkers) {
		s.loginWorkers <- struct{}{}
	}
	for i := 0; i < 6; i++ {
		r := httptest.NewRequest("POST", "/api/v1/login", strings.NewReader(fmt.Sprintf(`{"username":"fixture-%d@example.invalid","password":"fixture-password"}`, i)))
		r.RemoteAddr = "198.18.0.1:12345"
		w := httptest.NewRecorder()
		s.login(w, r)
		if w.Code != 429 {
			t.Fatalf("unexpected status: %d", w.Code)
		}
		if i < 5 && !strings.Contains(w.Body.String(), "登录请求较多") {
			t.Fatal("full bucket storage refused new source before worker admission")
		}
		if i == 5 && !strings.Contains(w.Body.String(), "登录尝试过于频繁") {
			t.Fatal("new source bypassed per-IP rate limit")
		}
	}
	if len(s.loginBuckets) != maxLoginBuckets {
		t.Fatal("fixed bucket storage grew")
	}
}

func TestLoginBucketRotationDoesNotResetKnownLimits(t *testing.T) {
	now := time.Now()
	for _, key := range []string{"ip:198.18.0.1", "account:fixture@example.invalid"} {
		s := New(nil)
		for range 5 {
			if !s.allowLogin(key, now, 5) {
				t.Fatal("initial burst rejected")
			}
		}
		for i := 0; i < maxLoginBuckets*2; i++ {
			s.allowLogin(fmt.Sprintf("account:rotation-%d", i), now, 5)
		}
		if s.allowLogin(key, now, 5) {
			t.Fatal("rotating keys reset a rate-limited source")
		}
		if len(s.loginBuckets) > maxLoginBuckets {
			t.Fatal("storage is unbounded")
		}
	}
}
