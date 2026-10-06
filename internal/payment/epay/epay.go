// Package epay implements the classic EPay V1 submit.php/MD5 protocol.
package epay

import (
	"context"
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/nekopass/nekopass/internal/payment"
)

type Driver struct{}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var parameterName = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

func merchantID(raw string) string {
	for _, char := range raw {
		if char < '0' || char > '9' {
			return raw
		}
	}
	result := strings.TrimLeft(raw, "0")
	if result == "" {
		return "0"
	}
	return result
}

func (Driver) Definition() payment.Definition {
	return payment.Definition{ID: "epay", Name: "EPay（V1 / MD5）", Fields: []payment.Field{
		{Name: "url", Label: "URL", Placeholder: "https://pay.example.com/ 或完整 submit.php 地址", Required: true},
		{Name: "pid", Label: "PID", Placeholder: "商户 ID", Required: true},
		{Name: "key", Label: "KEY", Placeholder: "商户密钥", Secret: true, Required: true},
		{Name: "type", Label: "TYPE", Placeholder: "alipay、wxpay、qqpay；留空进入收银台"},
	}}
}
func endpoint(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("URL 须为 HTTP(S) 地址，不能包含账号、查询参数或片段")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if strings.HasSuffix(u.Path, "/submit.php") {
		u.Path = strings.TrimSuffix(u.Path, "/submit.php")
	}
	u.Path = strings.TrimSuffix(path.Clean("/"+u.Path), "/") + "/submit.php"
	u.RawPath = ""
	return u, nil
}
func (Driver) Validate(c payment.Config) error {
	if _, e := endpoint(c["url"]); e != nil {
		return e
	}
	if !identifier.MatchString(c["pid"]) || strings.TrimSpace(c["key"]) == "" || len(c["key"]) > 512 || strings.ContainsAny(c["key"], "\r\n\x00") {
		return errors.New("请填写有效 PID 和 KEY")
	}
	if c["type"] != "" && !identifier.MatchString(c["type"]) {
		return errors.New("TYPE 格式无效")
	}
	for key := range c {
		if key != "url" && key != "pid" && key != "key" && key != "type" {
			return errors.New("支付配置包含不支持的参数")
		}
	}
	return nil
}
func (d Driver) AccountScope(c payment.Config) string {
	u, _ := endpoint(c["url"])
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" && port != "80" && port != "443" {
		host += ":" + port
	}
	pid := merchantID(c["pid"])
	return d.Definition().ID + "\n" + host + "\n" + u.Path + "\n" + pid
}

// Sign follows EPay V1: sort names, omit sign/sign_type/empty values, join
// decoded values without URL encoding, append KEY and compute lowercase MD5.
func Sign(c payment.Config, v url.Values) string {
	names := []string{}
	for key := range v {
		if key != "sign" && key != "sign_type" && v.Get(key) != "" {
			names = append(names, key)
		}
	}
	sort.Strings(names)
	parts := []string{}
	for _, key := range names {
		parts = append(parts, key+"="+v.Get(key))
	}
	sum := md5.Sum([]byte(strings.Join(parts, "&") + c["key"]))
	return hex.EncodeToString(sum[:])
}
func (d Driver) Create(_ context.Context, c payment.Config, o payment.Order) (payment.Checkout, error) {
	if e := d.Validate(c); e != nil {
		return payment.Checkout{}, e
	}
	if o.Currency != "CNY" {
		return payment.Checkout{}, errors.New("EPay 首版仅支持 CNY")
	}
	u, _ := endpoint(c["url"])
	values := url.Values{"pid": {merchantID(c["pid"])}, "type": {c["type"]}, "out_trade_no": {o.Number}, "notify_url": {o.NotifyURL}, "return_url": {o.ReturnURL}, "name": {o.Name}, "money": {o.Amount}, "sign_type": {"MD5"}}
	values.Set("sign", Sign(c, values))
	u.RawQuery = values.Encode()
	return payment.Checkout{URL: u.String()}, nil
}
func values(r payment.Callback) (url.Values, error) {
	result := url.Values{}
	for key, v := range r.Query {
		result[key] = append([]string{}, v...)
	}
	if r.Method == http.MethodPost {
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || contentType != "application/x-www-form-urlencoded" {
			return nil, errors.New("invalid notification content type")
		}
		body, e := url.ParseQuery(string(r.Body))
		if e != nil {
			return nil, e
		}
		for key, v := range body {
			result[key] = append(result[key], v...)
		}
	} else if r.Method != http.MethodGet {
		return nil, errors.New("invalid notification method")
	}
	if len(result) > 40 {
		return nil, errors.New("too many notification fields")
	}
	for key, v := range result {
		if len(v) != 1 || !parameterName.MatchString(key) || len(v[0]) > 4096 {
			return nil, errors.New("duplicate or oversized notification field")
		}
	}
	return result, nil
}
func (d Driver) Reference(r payment.Callback) (string, error) {
	v, e := values(r)
	if e != nil {
		return "", e
	}
	ref := v.Get("out_trade_no")
	if !identifier.MatchString(ref) {
		return "", errors.New("invalid order reference")
	}
	return ref, nil
}
func (d Driver) Verify(c payment.Config, r payment.Callback) (payment.Receipt, error) {
	if err := d.Validate(c); err != nil {
		return payment.Receipt{}, errors.New("invalid merchant configuration")
	}
	v, e := values(r)
	if e != nil {
		return payment.Receipt{}, e
	}
	signature, e := hex.DecodeString(v.Get("sign"))
	expected, _ := hex.DecodeString(Sign(c, v))
	if e != nil || len(signature) != md5.Size || subtle.ConstantTimeCompare(signature, expected) != 1 || (v.Get("sign_type") != "" && !strings.EqualFold(v.Get("sign_type"), "MD5")) || !identifier.MatchString(v.Get("pid")) || merchantID(v.Get("pid")) != merchantID(c["pid"]) || (c["type"] != "" && v.Get("type") != c["type"]) || v.Get("trade_status") != "TRADE_SUCCESS" || !identifier.MatchString(v.Get("trade_no")) || !identifier.MatchString(v.Get("out_trade_no")) || v.Get("money") == "" {
		return payment.Receipt{}, errors.New("invalid payment notification")
	}
	return payment.Receipt{OrderNumber: v.Get("out_trade_no"), TradeNumber: v.Get("trade_no"), Amount: v.Get("money"), Currency: "CNY"}, nil
}
func (Driver) Acknowledge(ok bool) payment.Response {
	if ok {
		return payment.Response{Status: 200, ContentType: "text/plain; charset=utf-8", Body: "success"}
	}
	return payment.Response{Status: 400, ContentType: "text/plain; charset=utf-8", Body: "fail"}
}
