package release

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionComparison(t *testing.T) {
	for _, c := range []struct {
		target, current string
		want            bool
	}{{"v0.10.0", "v0.9.0", true}, {"v1.0.0", "v0.99.0", true}, {"v0.10.0", "v0.10.0", false}, {"v0.9.0", "v0.10.0", false}, {"v0.10.0", "dev", true}, {"evil", "v0.9.0", false}} {
		if Newer(c.target, c.current) != c.want {
			t.Fatal(c)
		}
	}
}
func TestLatestRequiresCompleteOfficialAssets(t *testing.T) {
	for _, bad := range []string{"", "missing", "foreign", "draft", "prerelease", "invalid-tag"} {
		t.Run(bad, func(t *testing.T) {
			version := "v0.10.0"
			var assets []map[string]string
			for _, name := range []string{"nekopass-agent-linux-amd64", "nekopass-agent-linux-arm64", "nekopass-panel-linux-amd64.tar.gz", "nekopass-panel-linux-arm64.tar.gz", "install-agent.sh", "install-panel.sh"} {
				assets = append(assets, map[string]string{"name": name, "browser_download_url": DownloadBase + "/" + version + "/" + name})
			}
			if bad == "missing" {
				assets = assets[1:]
			}
			if bad == "foreign" {
				assets[0]["browser_download_url"] = "https://evil.example/file"
			}
			if bad == "invalid-tag" {
				version = "../oops"
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"tag_name": version, "assets": assets, "draft": bad == "draft", "prerelease": bad == "prerelease"})
			}))
			defer s.Close()
			c := &Client{HTTP: s.Client(), API: s.URL}
			info, err := c.Latest(context.Background())
			if (err == nil) != (bad == "") {
				t.Fatalf("unexpected release validity %v", err)
			}
			if err == nil && info.Version != version {
				t.Fatal("version lost")
			}
		})
	}
}
