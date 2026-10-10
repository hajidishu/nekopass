package ddns

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAddressRetriesThreeTimesAndStopsAfterSuccess(t *testing.T) {
	for _, failures := range []int32{0, 1, 2, 3} {
		t.Run(fmt.Sprint(failures), func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) <= failures {
					http.Error(w, "unavailable", 503)
					return
				}
				fmt.Fprint(w, "203.0.113.7")
			}))
			defer server.Close()
			c := &Client{IPv4: server.Client()}
			address, err := c.AddressWithRetry(context.Background(), server.URL, false)
			if attempts.Load() != min(failures+1, 3) || (err != nil) != (failures == 3) || failures < 3 && address != "203.0.113.7" {
				t.Fatal("incorrect retries", attempts.Load(), address, err)
			}
		})
	}
}

func TestAddressRetryCancellationStopsFurtherRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		cancel()
		http.Error(w, "unavailable", 503)
	}))
	defer server.Close()
	c := &Client{IPv4: server.Client()}
	if _, err := c.AddressWithRetry(ctx, server.URL, false); err == nil || attempts.Load() != 1 {
		t.Fatal("canceled retry continued", err, attempts.Load())
	}
}
