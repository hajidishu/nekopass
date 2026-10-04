package release

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var Version = "dev"

const Repository = "hajidishu/nekopass"
const DownloadBase = "https://github.com/" + Repository + "/releases/download"
const LatestBase = "https://github.com/" + Repository + "/releases/latest/download"

var tag = regexp.MustCompile(`^v([0-9]{1,8})\.([0-9]{1,8})\.([0-9]{1,8})$`)

func ValidVersion(v string) bool { return tag.MatchString(v) }
func Newer(target, current string) bool {
	a, b := tag.FindStringSubmatch(target), tag.FindStringSubmatch(current)
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x > y
		}
	}
	return false
}

type Info struct {
	Version     string `json:"version"`
	URL         string `json:"url"`
	PublishedAt string `json:"published_at"`
}
type Client struct {
	HTTP *http.Client
	API  string
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 15 * time.Second}, API: "https://api.github.com/repos/" + Repository + "/releases/latest"}
}
func (c *Client) Latest(ctx context.Context) (Info, error) {
	var out Info
	r, err := http.NewRequestWithContext(ctx, "GET", c.API, nil)
	if err != nil {
		return out, errors.New("GitHub 更新地址无效")
	}
	r.Header.Set("Accept", "application/vnd.github+json")
	r.Header.Set("User-Agent", "Nekopass/"+Version)
	response, err := c.HTTP.Do(r)
	if err != nil {
		return out, errors.New("无法连接 GitHub，请稍后重试")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return out, errors.New("GitHub 未提供正式版本，或 API 请求受限")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return out, errors.New("GitHub 版本响应无效")
	}
	var raw struct {
		Tag         string `json:"tag_name"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
		PublishedAt string `json:"published_at"`
		Assets      []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if json.Unmarshal(data, &raw) != nil || raw.Draft || raw.Prerelease || !ValidVersion(raw.Tag) {
		return out, errors.New("GitHub 正式版本无效")
	}
	expected := map[string]bool{"nekopass-agent-linux-amd64": false, "nekopass-agent-linux-arm64": false, "nekopass-panel-linux-amd64.tar.gz": false, "nekopass-panel-linux-arm64.tar.gz": false, "install-agent.sh": false, "install-panel.sh": false}
	for _, asset := range raw.Assets {
		if _, ok := expected[asset.Name]; ok && asset.URL == DownloadBase+"/"+raw.Tag+"/"+asset.Name {
			expected[asset.Name] = true
		}
	}
	for _, found := range expected {
		if !found {
			return out, errors.New("GitHub 发布文件尚未齐备")
		}
	}
	out = Info{Version: raw.Tag, URL: "https://github.com/" + Repository + "/releases/tag/" + raw.Tag, PublishedAt: strings.TrimSpace(raw.PublishedAt)}
	return out, nil
}
