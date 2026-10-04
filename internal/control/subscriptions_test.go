package control

import (
	"testing"
	"time"
)

func billingDate(s string) time.Time {
	t, e := time.ParseInLocation("2006-01-02 15:04", s, billingZone)
	if e != nil {
		panic(e)
	}
	return t
}
func TestRenewalConsumesCurrentRemainder(t *testing.T) {
	now := billingDate("2026-09-20 12:00")
	end := billingDate("2026-10-01 12:00")
	expires, next, e := purchasedDates(now, subscriptionState{Managed: true, Expires: &end, NextReset: &end}, true, "monthly")
	want := billingDate("2026-10-20 12:00")
	if e != nil || !expires.Equal(want) || !next.Equal(want) {
		t.Fatal(expires, next, e)
	}
	now = billingDate("2026-01-20 12:00")
	end = billingDate("2027-01-01 12:00")
	reset := billingDate("2026-02-01 12:00")
	expires, next, e = purchasedDates(now, subscriptionState{Managed: true, Expires: &end, NextReset: &reset}, true, "annual")
	if e != nil || !expires.Equal(billingDate("2027-12-20 12:00")) || !next.Equal(billingDate("2026-02-20 12:00")) {
		t.Fatal(expires, next, e)
	}
}
func TestBillingMonthEndsAndPermanentQuota(t *testing.T) {
	anchor := billingDate("2028-01-31 23:00")
	if got := addBillingMonths(anchor, 1); !got.Equal(billingDate("2028-02-29 23:00")) {
		t.Fatal(got)
	}
	if got := addBillingMonths(anchor, 2); !got.Equal(billingDate("2028-03-31 23:00")) {
		t.Fatal(got)
	}
	exp, next, e := purchasedDates(anchor, subscriptionState{}, false, "onetime")
	if e != nil || exp != nil || next != nil {
		t.Fatal("permanent quota unexpectedly scheduled", exp, next, e)
	}
	exp, next, e = purchasedDates(anchor, subscriptionState{}, false, "quarterly")
	if e != nil || !exp.Equal(billingDate("2028-04-30 23:00")) || !next.Equal(billingDate("2028-02-29 23:00")) {
		t.Fatal(exp, next, e)
	}
}
