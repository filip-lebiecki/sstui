package ui

import (
	"fmt"
	"strconv"
	"strings"

	"ss-stats-tui/model"
	"ss-stats-tui/poller"

	"github.com/charmbracelet/lipgloss"
)

// keepaliveSeconds returns the keepalive timer in seconds (-1 if not a
// keepalive timer or unparseable).
func keepaliveSeconds(c *model.Connection) float64 {
	if c.TimerType == nil || c.TimerDur == nil || *c.TimerType != "keepalive" {
		return -1
	}
	s := *c.TimerDur
	var mult float64
	switch {
	case strings.HasSuffix(s, "min"):
		mult = 60
		s = strings.TrimSuffix(s, "min")
	case strings.HasSuffix(s, "ms"):
		mult = 0.001
		s = strings.TrimSuffix(s, "ms")
	case strings.HasSuffix(s, "sec"):
		mult = 1
		s = strings.TrimSuffix(s, "sec")
	case strings.HasSuffix(s, "s"):
		mult = 1
		s = strings.TrimSuffix(s, "s")
	default:
		return -1
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return f * mult
}

func fmtKeepalive(c *model.Connection) string {
	v := keepaliveSeconds(c)
	if v < 0 {
		return "-"
	}
	if v >= 60 {
		return fmt.Sprintf("%dm%02ds", int(v)/60, int(v)%60)
	}
	if v >= 1 {
		return fmt.Sprintf("%.0fs", v)
	}
	return fmt.Sprintf("%.0fms", v*1000)
}

// Format helpers for display values.

func fmtNum(v *int) string {
	if v == nil {
		return "-"
	}
	switch {
	case *v >= 1_000_000_000:
		return fmt.Sprintf("%.1fG", float64(*v)/1e9)
	case *v >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(*v)/1e6)
	case *v >= 1_000:
		return fmt.Sprintf("%.1fK", float64(*v)/1e3)
	default:
		return strconv.Itoa(*v)
	}
}

func fmtNumRaw(v *int) string {
	if v == nil {
		return "-"
	}
	return strconv.Itoa(*v)
}

func fmtFloat(v *float64, prec int) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%."+strconv.Itoa(prec)+"f", *v)
}

func fmtRTT(v *float64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f", *v)
}

func fmtBPS(v *int) string {
	if v == nil {
		return "-"
	}
	bps := float64(*v)
	switch {
	case bps >= 1_000_000_000:
		return fmt.Sprintf("%.1fGbps", bps/1e9)
	case bps >= 1_000_000:
		return fmt.Sprintf("%.1fMbps", bps/1e6)
	case bps >= 1_000:
		return fmt.Sprintf("%.1fKbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0fbps", bps)
	}
}

func fmtBytes(v *int) string {
	if v == nil {
		return "-"
	}
	b := float64(*v)
	switch {
	case b >= 1_073_741_824:
		return fmt.Sprintf("%.1fG", b/1073741824)
	case b >= 1_048_576:
		return fmt.Sprintf("%.1fM", b/1048576)
	case b >= 1024:
		return fmt.Sprintf("%.1fK", b/1024)
	default:
		return fmt.Sprintf("%.0fB", b)
	}
}

func fmtRate(v *int) string {
	if v == nil {
		return "-"
	}
	b := float64(*v) / poller.PollInterval.Seconds()
	switch {
	case b >= 1_000_000:
		return fmt.Sprintf("%.1fMB/s", b/1e6)
	case b >= 1_000:
		return fmt.Sprintf("%.1fKB/s", b/1e3)
	default:
		return fmt.Sprintf("%.0fB/s", b)
	}
}

func fmtPill(label, value string) string {
	return fmt.Sprintf(" %s: %s ", label, value)
}

// fmtPackets renders a packet count with the "pkts" suffix.
func fmtPackets(v *int) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%d pkts", *v)
}

// fmtSSThresh handles the kernel's TCP_INFINITE_SSTHRESH sentinel.
func fmtSSThresh(v *int) string {
	if v == nil {
		return "-"
	}
	if *v >= 0x7fffffff {
		return "∞ (slow start)"
	}
	return fmt.Sprintf("%d pkts", *v)
}

// fmtSegRate renders a segments-per-poll delta as segments/s.
func fmtSegRate(v *int) string {
	if v == nil {
		return "-"
	}
	r := float64(*v) / poller.PollInterval.Seconds()
	return fmt.Sprintf("%.0f seg/s", r)
}

// portService maps well-known ports to a short protocol/service name.
var portService = map[string]string{
	"22": "SSH", "25": "SMTP", "53": "DNS", "67": "DHCP", "68": "DHCP",
	"80": "HTTP", "110": "POP3", "123": "NTP", "143": "IMAP", "161": "SNMP",
	"389": "LDAP", "443": "HTTPS", "445": "SMB", "465": "SMTPS", "514": "SYSLOG",
	"587": "SUBMIT", "636": "LDAPS", "853": "DoT", "993": "IMAPS", "995": "POP3S",
	"1080": "SOCKS", "1194": "OVPN", "1433": "MSSQL", "1812": "RADIUS",
	"2049": "NFS", "3000": "DEV", "3306": "MYSQL", "3389": "RDP", "4040": "DEV",
	"4444": "DEV", "5000": "DEV", "5060": "SIP", "5173": "VITE", "5353": "MDNS",
	"5432": "POSTGRES", "5672": "AMQP", "5900": "VNC", "5938": "TEAMV",
	"6379": "REDIS", "6443": "K8S", "8000": "DEV", "8080": "HTTP-A",
	"8443": "HTTPS-A", "8888": "DEV", "9000": "DEV", "9090": "PROM",
	"9092": "KAFKA", "9200": "ES", "11211": "MEMCACHE", "27017": "MONGO",
	"51820": "WG",
}

// PortServiceName returns the service for a port, or "" if unknown.
func PortServiceName(port string) string {
	return portService[port]
}

// fmtRatioBar renders an inline horizontal progress bar for ratios in [0, 1].
// Values above 1 saturate. Color shifts from green → yellow → orange → red
// as the ratio climbs.
func fmtRatioBar(ratio float64, width int) string {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio*float64(width) + 0.5)
	if filled > width {
		filled = width
	}
	var c string
	switch {
	case ratio >= 0.9:
		c = "#ff6b6b"
	case ratio >= 0.7:
		c = "#ffa94d"
	case ratio >= 0.5:
		c = "#ffd43b"
	default:
		c = "#51cf66"
	}
	filledStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(c))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#444"))
	return filledStyle.Render(strings.Repeat("█", filled)) +
		dimStyle.Render(strings.Repeat("░", width-filled))
}

// fmtPropBar renders a proportional bar for `value` against `max`, width cells.
// Uses the same color gradient as fmtRatioBar (green → yellow → orange → red).
func fmtPropBar(value, max float64, width int) string {
	if max <= 0 {
		return strings.Repeat(" ", width)
	}
	return fmtRatioBar(value/max, width)
}

// fmtMs renders an int millisecond value with "ms" or seconds when large.
func fmtMs(v *int) string {
	if v == nil {
		return "-"
	}
	if *v >= 1000 {
		return fmt.Sprintf("%.1fs", float64(*v)/1000)
	}
	return fmt.Sprintf("%dms", *v)
}
