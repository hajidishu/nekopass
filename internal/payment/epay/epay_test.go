package epay

import (
	"context"
	"github.com/nekopass/nekopass/internal/payment"
	"net/http"
	"net/url"
	"testing"
)

func fixture() payment.Config {
	return payment.Config{"url": "https://gateway.example.test/", "pid": "1001", "key": "fixture-epay-key-not-real", "type": "alipay"}
}
func notification(c payment.Config) url.Values {
	v := url.Values{"pid": {c["pid"]}, "out_trade_no": {"Rfixture-order"}, "trade_no": {"fixture-trade"}, "type": {"alipay"}, "money": {"10.00"}, "trade_status": {"TRADE_SUCCESS"}, "sign_type": {"MD5"}}
	v.Set("sign", Sign(c, v))
	return v
}
func TestSigningSubmissionAndNotification(t *testing.T) {
	// Independent protocol vector: decoded UTF-8, spaces/plus signs, empty and
	// signature fields. Expected digest is fixed, not computed by this signer.
	vector := url.Values{"c": {"x+y"}, "b": {"a b"}, "a": {"中文"}, "z": {""}, "sign": {"ignored"}, "sign_type": {"ignored"}}
	if Sign(fixture(), vector) != "04571db56deb30ffa954f3ae9235cbc0" {
		t.Fatal("EPay canonical signing vector mismatch")
	}
	d := Driver{}
	c := fixture()
	checkout, e := d.Create(context.Background(), c, payment.Order{Number: "Rfixture-order", Amount: "10.00", Currency: "CNY", Name: "余额充值", NotifyURL: "https://panel.example.test/notify", ReturnURL: "https://panel.example.test/return"})
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(checkout.URL)
	if e != nil || u.Path != "/submit.php" || u.Query().Get("money") != "10.00" || u.Query().Get("sign") != Sign(c, u.Query()) || u.Query().Has("key") {
		t.Fatal("invalid checkout", e)
	}
	values := notification(c)
	receipt, e := d.Verify(c, payment.Callback{Method: "GET", Query: values})
	if e != nil || receipt.Amount != "10.00" || receipt.TradeNumber != "fixture-trade" {
		t.Fatal(receipt, e)
	}
	for _, field := range []string{"pid", "money", "trade_status", "out_trade_no", "trade_no", "type"} {
		bad := url.Values{}
		for key, v := range values {
			bad[key] = append([]string{}, v...)
		}
		bad.Set(field, "tampered")
		if _, e = d.Verify(c, payment.Callback{Method: "GET", Query: bad}); e == nil {
			t.Fatal("tampering accepted", field)
		}
	}
	duplicate := notification(c)
	duplicate.Add("money", "10.00")
	if _, e = d.Verify(c, payment.Callback{Method: "GET", Query: duplicate}); e == nil {
		t.Fatal("duplicate parameters accepted")
	}
	if _, e = d.Verify(c, payment.Callback{Method: "POST", Query: notification(c), Body: []byte("money=10.00"), Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}}); e == nil {
		t.Fatal("query/body collision accepted")
	}
	post := payment.Callback{Method: "POST", Body: []byte(notification(c).Encode()), Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}}
	if _, e = d.Verify(c, post); e != nil {
		t.Fatal(e)
	}
}
func TestGatewayScopeAndValidation(t *testing.T) {
	d := Driver{}
	a := fixture()
	b := fixture()
	b["type"] = "wxpay"
	b["url"] = "http://GATEWAY.example.test:80/submit.php"
	b["key"] = "fixture-different-key"
	if d.AccountScope(a) != d.AccountScope(b) {
		t.Fatal("same merchant split across methods or key rotations")
	}
	for _, raw := range []string{"javascript:alert(1)", "https://user:pass@gateway.example.test/", "https://gateway.example.test/?key=unsafe", "https://gateway.example.test/#fragment"} {
		c := fixture()
		c["url"] = raw
		if d.Validate(c) == nil {
			t.Fatal("invalid URL accepted")
		}
	}
}

func TestInvalidCredentialsAndParameterNamesCannotAuthenticate(t *testing.T) {
	d := Driver{}
	for _, key := range []string{"", "   "} {
		c := fixture()
		c["key"] = key
		v := notification(c)
		if d.Validate(c) == nil {
			t.Fatal("blank merchant key accepted")
		}
		if _, e := d.Verify(c, payment.Callback{Method: "GET", Query: v}); e == nil {
			t.Fatal("unconfigured merchant accepted a computable signature")
		}
	}
	for _, name := range []string{"money&pid", "sign=money", "\r\nparam", ""} {
		c := fixture()
		v := notification(c)
		v.Set(name, "injected")
		v.Set("sign", Sign(c, v))
		if _, e := d.Verify(c, payment.Callback{Method: "GET", Query: v}); e == nil {
			t.Fatal("ambiguous canonical parameter name accepted")
		}
	}
}

func TestNumericMerchantRepresentationAndEndpointAliases(t *testing.T) {
	d := Driver{}
	c := fixture()
	c["pid"] = "0001001"
	v := notification(c)
	v.Set("pid", "1001")
	v.Set("sign", Sign(c, v))
	if _, e := d.Verify(c, payment.Callback{Method: "GET", Query: v}); e != nil {
		t.Fatal("numeric PID normalization rejected valid payment", e)
	}
	checkout, e := d.Create(context.Background(), c, payment.Order{Currency: "CNY", Number: "Rfixture", Amount: "10.00"})
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(checkout.URL)
	if u.Query().Get("pid") != "1001" {
		t.Fatal("submission PID not canonical")
	}
	original := fixture()
	if d.AccountScope(c) != d.AccountScope(original) {
		t.Fatal("numeric aliases split transaction scope")
	}
	c["pid"] = "0merchant"
	original["pid"] = "merchant"
	if d.AccountScope(c) == d.AccountScope(original) {
		t.Fatal("distinct textual merchant IDs collapsed")
	}
	c["url"] = "https://gateway.example.test/submit.php/"
	u, e = endpoint(c["url"])
	if e != nil || u.Path != "/submit.php" {
		t.Fatal("trailing slash duplicates submission path", e)
	}
}
