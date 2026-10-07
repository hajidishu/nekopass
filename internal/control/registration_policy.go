package control

import (
	"net/url"
	"strings"
)

func legalURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil && !strings.ContainsAny(raw, "\r\n\x00 \t")
}
