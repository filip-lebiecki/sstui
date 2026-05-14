package ui

import (
	"fmt"
	"strconv"

	"ss-stats-tui/poller"
)

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
