package poller

import (
	"os"
	"path/filepath"
	"strings"
)

// SysctlKeys are the kernel settings the Findings tab reasons about: accept
// and SYN backlogs, ephemeral ports / TIME-WAIT reuse, socket buffer limits,
// window scaling, congestion control and queueing discipline.
var SysctlKeys = []string{
	"net.core.somaxconn",
	"net.ipv4.tcp_max_syn_backlog",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.tcp_tw_reuse",
	"net.ipv4.tcp_fin_timeout",
	"net.core.rmem_max",
	"net.core.wmem_max",
	"net.core.rmem_default",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
	"net.ipv4.tcp_mem",
	"net.ipv4.tcp_window_scaling",
	"net.ipv4.tcp_congestion_control",
	"net.ipv4.tcp_available_congestion_control",
	"net.core.default_qdisc",
	"net.ipv4.tcp_mtu_probing",
}

// Sysctls maps a dotted sysctl name to its value with whitespace collapsed
// (multi-value settings like tcp_rmem become "4096 131072 6291456"). Keys
// that couldn't be read are absent.
type Sysctls map[string]string

// ReadSysctls reads SysctlKeys from /proc/sys. Best-effort: unreadable keys
// (other namespaces, older kernels) are simply missing.
func ReadSysctls() Sysctls { return readSysctlsFrom("/proc/sys") }

func readSysctlsFrom(root string) Sysctls {
	out := make(Sysctls, len(SysctlKeys))
	for _, k := range SysctlKeys {
		data, err := os.ReadFile(filepath.Join(root, strings.ReplaceAll(k, ".", "/")))
		if err != nil {
			continue
		}
		out[k] = strings.Join(strings.Fields(string(data)), " ")
	}
	return out
}

// Int returns the first integer of a sysctl value (e.g. somaxconn), or ok=false.
func (s Sysctls) Int(key string) (int, bool) {
	vals := s.Ints(key)
	if len(vals) == 0 {
		return 0, false
	}
	return vals[0], true
}

// Ints returns all integers of a multi-value sysctl (e.g. tcp_rmem's
// min/default/max triple). Non-integer parts stop the parse.
func (s Sysctls) Ints(key string) []int {
	var out []int
	for _, f := range strings.Fields(s[key]) {
		n := 0
		for _, r := range f {
			if r < '0' || r > '9' {
				return out
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}
