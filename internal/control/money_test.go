package control

import "testing"

func TestMoneyUsesExactCents(t *testing.T) {
	for raw, want := range map[string]int64{"0": 0, "0.01": 1, "0.29": 29, "9.9": 990, "100.00": 10000, "1000000000.00": maxMoneyCents} {
		got, err := parseMoney(raw)
		if err != nil || got != want {
			t.Fatalf("%s: got %d, %v", raw, got, err)
		}
		back, err := parseMoney(formatMoney(got))
		if err != nil || back != want {
			t.Fatalf("roundtrip %s", raw)
		}
	}
	for _, raw := range []string{"", " 1", "1 ", "-1", "+1", "01", "1e3", "NaN", "0.001", "1000000000.01", "999999999999999999999"} {
		if _, err := parseMoney(raw); err == nil {
			t.Fatalf("accepted invalid amount %q", raw)
		}
	}
}

func TestPlanPricesDistinguishFreeFromNotForSale(t *testing.T) {
	blank, free, annual := "", "0", "60.00"
	prices, err := parsePlanPrices(map[string]*string{"monthly": &blank, "quarterly": nil, "annual": &annual, "onetime": &free})
	if err != nil || len(prices) != 2 || prices["annual"] != 6000 {
		t.Fatal(prices, err)
	}
	if value, ok := prices["onetime"]; !ok || value != 0 {
		t.Fatal("free period became unavailable")
	}
	if _, err = parsePlanPrices(map[string]*string{"reset": &annual}); err == nil {
		t.Fatal("reset package accepted")
	}
}
