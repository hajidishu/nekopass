package control

import (
	"fmt"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/telegram"
	"html"
	"math"
	"strings"
	"time"
)

func tgText(s string) string { return html.EscapeString(s) }
func tgBytes(n int64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	}
	return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
}
func tgBar(percent float64) string {
	n := int(math.Round(max(0, min(100, percent)) / 10))
	return strings.Repeat("▰", n) + strings.Repeat("▱", 10-n)
}
func telegramMetrics(p *pb.Probe) string {
	if p == nil || !validProbe(p) {
		return "探针数据暂未上报"
	}
	lines := []string{}
	if p.CpuReady {
		lines = append(lines, fmt.Sprintf("CPU  %.1f%%  %s", p.CpuPercent, tgBar(p.CpuPercent)))
	} else {
		lines = append(lines, "CPU  采集中")
	}
	for _, item := range []struct {
		label       string
		used, total int64
		ready       bool
	}{{"内存", p.MemoryUsed, p.MemoryTotal, p.MemoryReady}, {"磁盘", p.DiskUsed, p.DiskTotal, p.DiskReady}} {
		if item.ready && item.total > 0 {
			percent := float64(item.used) * 100 / float64(item.total)
			lines = append(lines, fmt.Sprintf("%s  %s / %s · %.1f%%", item.label, tgBytes(item.used), tgBytes(item.total), percent))
		} else {
			lines = append(lines, item.label+"  暂无数据")
		}
	}
	if p.NetworkReady {
		lines = append(lines, fmt.Sprintf("网络  ↓ %.2f Mbps  ↑ %.2f Mbps", p.RxMbps, p.TxMbps))
	}
	if p.ConnectionsReady {
		lines = append(lines, fmt.Sprintf("连接  TCP %d · UDP %d", p.TcpConnections, p.UdpSockets))
	}
	if p.LoadReady {
		lines = append(lines, fmt.Sprintf("负载  %.2f / %.2f / %.2f", p.Load1, p.Load5, p.Load15))
	}
	return strings.Join(lines, "\n")
}

func telegramHomeKeyboard(panelURL string) *telegram.Keyboard {
	rows := [][]telegram.Button{{{Text: "📡 节点信息", Data: "nodes:0"}, {Text: "🔄 刷新面板", Data: "home"}}, {{Text: "📬 通知设置", Data: "notifications"}}}
	if panelURL != "" && panelURLValidForTelegram(panelURL) {
		rows = append(rows, []telegram.Button{{Text: "🌐 打开面板", URL: panelURL}})
	}
	return &telegram.Keyboard{Rows: rows}
}
func panelURLValidForTelegram(v string) bool { return panelURL(v) }
func telegramNodesKeyboard(page, pages int) *telegram.Keyboard {
	row := []telegram.Button{}
	if page > 0 {
		row = append(row, telegram.Button{Text: "◀ 上一页", Data: fmt.Sprintf("nodes:%d", page-1)})
	}
	if page+1 < pages {
		row = append(row, telegram.Button{Text: "下一页 ▶", Data: fmt.Sprintf("nodes:%d", page+1)})
	}
	rows := [][]telegram.Button{}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	rows = append(rows, []telegram.Button{{Text: "🔄 刷新本页", Data: fmt.Sprintf("nodes:%d", page)}, {Text: "🏠 面板概览", Data: "home"}})
	return &telegram.Keyboard{Rows: rows}
}

type telegramEvent struct {
	ID, NodeID, ChatID, Changes                                   int64
	Kind, Name, Old4, New4, Old6, New6, Record, State, ConfigHash string
	Created                                                       time.Time
	Attempts                                                      int
}

func formatTelegramEvent(e telegramEvent, days int) string {
	title := "🌐 节点 IP 已更换"
	if e.Kind == "ddns_error" {
		title = "⚠️ DDNS 同步失败"
	} else if e.Kind == "ddns_recovered" {
		title = "✅ DDNS 已恢复同步"
	}
	lines := []string{"<b>" + title + "</b>", "━━━━━━━━━━━━━━", "<b>节点</b>  " + tgText(e.Name)}
	for _, v := range []struct{ label, old, new string }{{"IPv4", e.Old4, e.New4}, {"IPv6", e.Old6, e.New6}} {
		if v.new != "" {
			text := "<code>" + tgText(v.new) + "</code>"
			if v.old != "" && v.old != v.new {
				text = "<code>" + tgText(v.old) + "</code> → " + text
			}
			lines = append(lines, "<b>"+v.label+"</b>  "+text)
		}
	}
	if e.Record != "" {
		lines = append(lines, "<b>域名</b>  <code>"+tgText(e.Record)+"</code>")
	}
	state := map[string]string{"ok": "✅ 已自动同步", "partial": "🟡 部分同步，详情见面板", "error": "❌ 同步失败，详情见面板", "pending": "⏳ 正在同步", "off": "未启用"}[e.State]
	if state == "" {
		state = "等待同步"
	}
	lines = append(lines, "<b>DDNS</b>  "+state, "<b>时间</b>  "+e.Created.In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02 15:04:05")+" (UTC+8)", "━━━━━━━━━━━━━━", fmt.Sprintf("📊 该节点近 %d 天已更换 %d 次 IP", days, e.Changes))
	return strings.Join(lines, "\n")
}
