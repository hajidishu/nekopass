package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCloudflareUpsertAndZoneDiscovery(t *testing.T) {
	for _, kind := range []string{"A", "AAAA"} {
		t.Run(kind, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.RecordName, cfg.Token = "node.example.com", "fixture-token"
			address := "203.0.113.7"
			if kind == "AAAA" {
				address = "2001:db8::7"
			}
			zone, record := strings.Repeat("a", 32), strings.Repeat("b", 32)
			var stored map[string]any
			var writes, lookups int
			var mu sync.Mutex
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Header.Get("Authorization") != "Bearer "+cfg.Token {
					t.Error("missing API authorization")
				}
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/zones" {
					lookups++
					if r.URL.Query().Get("status") != "active" {
						t.Error("zone filter lost")
					}
					if r.URL.Query().Get("name") == "example.com" {
						fmt.Fprintf(w, `{"success":true,"result":[{"id":%q,"name":"example.com"}]}`, zone)
					} else {
						fmt.Fprint(w, `{"success":true,"result":[]}`)
					}
					return
				}
				if !strings.HasPrefix(r.URL.Path, "/zones/"+zone+"/dns_records") {
					t.Error("wrong zone")
					http.Error(w, "wrong path", 400)
					return
				}
				if r.Method == "GET" {
					if r.URL.Query().Get("type") != kind || r.URL.Query().Get("name") != cfg.RecordName {
						t.Error("record filter lost")
					}
					if stored == nil {
						fmt.Fprint(w, `{"success":true,"result":[]}`)
					} else {
						json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{stored}})
					}
					return
				}
				writes++
				if writes == 1 && r.Method != "POST" || writes == 2 && (r.Method != "PATCH" || !strings.HasSuffix(r.URL.Path, "/"+record)) {
					t.Error("wrong write method")
				}
				if json.NewDecoder(r.Body).Decode(&stored) != nil {
					t.Error("invalid record payload")
				}
				if stored["proxied"] != false || stored["name"] != cfg.RecordName || stored["type"] != kind {
					t.Error("wrong record or proxy mode")
				}
				stored["id"] = record
				fmt.Fprint(w, `{"success":true,"result":{}}`)
			}))
			defer s.Close()
			c := &Client{APIBase: s.URL, API: s.Client()}
			found, err := c.Zone(context.Background(), cfg)
			if err != nil || found != zone || lookups != 2 {
				t.Fatalf("zone discovery failed: %v", err)
			}
			if changed, err := c.Sync(context.Background(), cfg, zone, kind, address); err != nil || !changed {
				t.Fatalf("create: %v", err)
			}
			if changed, err := c.Sync(context.Background(), cfg, zone, kind, address); err != nil || changed {
				t.Fatalf("unchanged record rewritten: %v", err)
			}
			// IP changes update the same record and correct its proxy mode.
			mu.Lock()
			stored["proxied"] = true
			mu.Unlock()
			nextAddress := "203.0.113.8"
			if kind == "AAAA" {
				nextAddress = "2001:db8::8"
			}
			if changed, err := c.Sync(context.Background(), cfg, zone, kind, nextAddress); err != nil || !changed {
				t.Fatalf("update: %v", err)
			}
			mu.Lock()
			if stored["content"] != nextAddress {
				t.Error("changed IP was not saved")
			}
			if writes != 2 {
				t.Fatal("unexpected writes")
			}
			mu.Unlock()
		})
	}
}

func TestAddressValidationAndNoTokenAtIPService(t *testing.T) {
	for _, tc := range []struct {
		body      string
		v6, valid bool
	}{
		{"203.0.113.7\n", false, true}, {"2001:db8::7", true, true}, {"::ffff:203.0.113.7", false, true},
		{"127.0.0.1", false, false}, {"192.168.1.1", false, false}, {"169.254.1.1", false, false},
		{"fc00::1", true, false}, {"fe80::1%eth0", true, false}, {"2001:db8::1", false, false}, {"not-an-ip", false, false}, {strings.Repeat("a", 257), false, false},
	} {
		t.Run(tc.body[:min(len(tc.body), 25)], func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("credential leaked to IP source")
				}
				fmt.Fprint(w, tc.body)
			}))
			defer s.Close()
			c := &Client{IPv4: s.Client(), IPv6: s.Client()}
			_, err := c.Address(context.Background(), s.URL, tc.v6)
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected validity: %v", err)
			}
		})
	}
}

func TestCloudflareRejectsDuplicateAndMismatchedRecords(t *testing.T) {
	for _, result := range []string{
		`[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]`,
		`[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"other.example.com","type":"A"}]`,
	} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Error("unsafe write")
			}
			fmt.Fprintf(w, `{"success":true,"result":%s}`, result)
		}))
		c := &Client{APIBase: s.URL, API: s.Client()}
		cfg := DefaultConfig()
		cfg.RecordName = "node.example.com"
		if _, err := c.Sync(context.Background(), cfg, strings.Repeat("a", 32), "A", "203.0.113.7"); err == nil {
			t.Error("unsafe record accepted")
		}
		s.Close()
	}
}

func TestCloudflareErrorsDoNotEchoResponseSecrets(t *testing.T) {
	for _, code := range []int{401, 403, 429, 500} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			fmt.Fprint(w, `{"success":false,"errors":[{"message":"fixture-private-token"}]}`)
		}))
		c := &Client{APIBase: s.URL, API: s.Client()}
		err := c.request(context.Background(), "GET", "/zones", "fixture-private-token", nil, nil)
		if err == nil || strings.Contains(err.Error(), "fixture-private-token") {
			t.Fatal("response details escaped")
		}
		s.Close()
	}
	// Production clients refuse redirects instead of forwarding credentials.
	var contacted bool
	end := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacted = true }))
	defer end.Close()
	start := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, end.URL, 302) }))
	defer start.Close()
	c := NewClient()
	defer c.Close()
	c.API.Transport = start.Client().Transport
	c.APIBase = start.URL
	if c.request(context.Background(), "GET", "/zones", "fixture-private-token", nil, nil) == nil || contacted {
		t.Fatal("followed DNS API redirect")
	}
}
