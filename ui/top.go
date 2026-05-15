package ui

import (
	"fmt"
	"sort"
	"strings"

	"sstui/model"
	"sstui/poller"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleTopHdr   = lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).Bold(true)
	styleTopProc  = lipgloss.NewStyle().Foreground(lipgloss.Color("#fff")).Bold(true)
	styleTopPort  = lipgloss.NewStyle().Foreground(lipgloss.Color("#74c0fc")).Bold(true)
	styleTopSvc   = lipgloss.NewStyle().Foreground(lipgloss.Color("#3bc9db"))
	styleTopAddr  = lipgloss.NewStyle().Foreground(lipgloss.Color("#adb5bd"))
	styleTopCount = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd43b"))
	styleTopTX    = lipgloss.NewStyle().Foreground(lipgloss.Color("#51cf66"))
	styleTopRX    = lipgloss.NewStyle().Foreground(lipgloss.Color("#da77f2"))
	styleTopWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff6b6b")).Bold(true)
	styleTopDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("#666"))
)

const topBarW = 15

// RenderTop renders rankings: top processes, ports, peers, TX/RX talkers.
func RenderTop(buf *poller.Buffer, width, height int) string {
	snap := buf.GetLatest()
	if snap == nil {
		return "\n  No data yet..."
	}

	var b strings.Builder

	b.WriteString(renderTopProcesses(snap))
	b.WriteString("\n")
	b.WriteString(renderTopPorts(snap))
	b.WriteString("\n")
	b.WriteString(renderTopPeers(snap))
	b.WriteString("\n")
	b.WriteString(renderTopTX(snap))
	b.WriteString("\n")
	b.WriteString(renderTopRX(snap))

	return b.String()
}

type procStats struct {
	name        string
	conns       int
	totalRTT    float64
	rttCount    int
	totalSent   float64
	totalRecv   float64
	issuesWarn  int
	issuesCrit  int
}

func renderTopProcesses(snap *poller.Snapshot) string {
	procs := make(map[string]*procStats)
	for _, c := range snap.Conns {
		name := "-"
		if c.Process != nil {
			name = *c.Process
		}
		ps, ok := procs[name]
		if !ok {
			ps = &procStats{name: name}
			procs[name] = ps
		}
		ps.conns++
		if c.RTT != nil {
			ps.totalRTT += *c.RTT
			ps.rttCount++
		}
		if c.DeltaBytesSent != nil {
			ps.totalSent += float64(*c.DeltaBytesSent)
		}
		if c.DeltaBytesReceived != nil {
			ps.totalRecv += float64(*c.DeltaBytesReceived)
		}
		for _, s := range c.Signals {
			switch s.Severity {
			case 1:
				ps.issuesWarn++
			case 2:
				ps.issuesCrit++
			}
		}
	}
	var psList []*procStats
	maxConns := 0
	for _, ps := range procs {
		psList = append(psList, ps)
		if ps.conns > maxConns {
			maxConns = ps.conns
		}
	}
	sort.Slice(psList, func(i, j int) bool { return psList[i].conns > psList[j].conns })
	if len(psList) > 15 {
		psList = psList[:15]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Top Processes") + "\n")
	sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s %s\n",
		styleTopHdr.Render(fmt.Sprintf("%-18s", "Process")),
		styleTopHdr.Render(fmt.Sprintf("%-5s", "Conns")),
		styleTopHdr.Render(fmt.Sprintf("%-*s", topBarW, "")),
		styleTopHdr.Render(fmt.Sprintf("%-8s", "Avg RTT")),
		styleTopHdr.Render(fmt.Sprintf("%-10s", "TX/s")),
		styleTopHdr.Render(fmt.Sprintf("%-10s", "RX/s")),
		styleTopHdr.Render("Issues")))
	for _, ps := range psList {
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s %s\n",
			styleTopProc.Render(fmt.Sprintf("%-18s", truncate(ps.name, 18))),
			styleTopCount.Render(fmt.Sprintf("%5d", ps.conns)),
			fmtPropBar(float64(ps.conns), float64(maxConns), topBarW),
			renderRTT(ps.totalRTT, ps.rttCount, 8),
			styleTopTX.Render(fmt.Sprintf("%-10s", fmtBytesPerSec(ps.totalSent))),
			styleTopRX.Render(fmt.Sprintf("%-10s", fmtBytesPerSec(ps.totalRecv))),
			renderIssues(ps.issuesWarn, ps.issuesCrit)))
	}
	if len(psList) == 0 {
		sb.WriteString("  None\n")
	}
	return sb.String()
}

func renderTopPorts(snap *poller.Snapshot) string {
	type portStats struct {
		port  string
		proto string
		conns int
	}
	ports := make(map[string]*portStats)
	for _, c := range snap.Conns {
		key := c.Protocol + ":" + c.LocalPort
		ps, ok := ports[key]
		if !ok {
			ps = &portStats{port: c.LocalPort, proto: c.Protocol}
			ports[key] = ps
		}
		ps.conns++
	}
	var psList []*portStats
	maxConns := 0
	for _, ps := range ports {
		psList = append(psList, ps)
		if ps.conns > maxConns {
			maxConns = ps.conns
		}
	}
	sort.Slice(psList, func(i, j int) bool { return psList[i].conns > psList[j].conns })
	if len(psList) > 15 {
		psList = psList[:15]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Top Local Ports") + "\n")
	sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
		styleTopHdr.Render(fmt.Sprintf("%-6s", "Proto")),
		styleTopHdr.Render(fmt.Sprintf("%-8s", "Port")),
		styleTopHdr.Render(fmt.Sprintf("%-12s", "Service")),
		styleTopHdr.Render(fmt.Sprintf("%-5s", "Conns")),
		styleTopHdr.Render("")))
	for _, ps := range psList {
		svc := PortServiceName(ps.port)
		if svc == "" {
			svc = "-"
		}
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
			lipgloss.NewStyle().Foreground(ProtoColor(ps.proto)).Render(fmt.Sprintf("%-6s", strings.ToUpper(ps.proto))),
			styleTopPort.Render(fmt.Sprintf("%-8s", ps.port)),
			styleTopSvc.Render(fmt.Sprintf("%-12s", svc)),
			styleTopCount.Render(fmt.Sprintf("%5d", ps.conns)),
			fmtPropBar(float64(ps.conns), float64(maxConns), topBarW)))
	}
	if len(psList) == 0 {
		sb.WriteString("  None\n")
	}
	return sb.String()
}

type peerStats struct {
	addr       string
	conns      int
	totalSent  float64
	totalRecv  float64
}

func renderTopPeers(snap *poller.Snapshot) string {
	peers := make(map[string]*peerStats)
	for _, c := range snap.Conns {
		if c.PeerAddr == "" || c.PeerAddr == "*" || c.PeerAddr == "0.0.0.0" || c.PeerAddr == "::" {
			continue
		}
		ps, ok := peers[c.PeerAddr]
		if !ok {
			ps = &peerStats{addr: c.PeerAddr}
			peers[c.PeerAddr] = ps
		}
		ps.conns++
		if c.BytesSent != nil {
			ps.totalSent += float64(*c.BytesSent)
		}
		if c.BytesReceived != nil {
			ps.totalRecv += float64(*c.BytesReceived)
		}
	}
	var psList []*peerStats
	maxConns := 0
	for _, ps := range peers {
		psList = append(psList, ps)
		if ps.conns > maxConns {
			maxConns = ps.conns
		}
	}
	sort.Slice(psList, func(i, j int) bool { return psList[i].conns > psList[j].conns })
	if len(psList) > 15 {
		psList = psList[:15]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Top Peer Hosts") + "\n")
	sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
		styleTopHdr.Render(fmt.Sprintf("%-40s", "Peer")),
		styleTopHdr.Render(fmt.Sprintf("%-5s", "Conns")),
		styleTopHdr.Render(fmt.Sprintf("%-*s", topBarW, "")),
		styleTopHdr.Render(fmt.Sprintf("%-10s", "Bytes Out")),
		styleTopHdr.Render("Bytes In")))
	for _, ps := range psList {
		out := int(ps.totalSent)
		in := int(ps.totalRecv)
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
			styleTopAddr.Render(fmt.Sprintf("%-40s", truncate(ps.addr, 40))),
			styleTopCount.Render(fmt.Sprintf("%5d", ps.conns)),
			fmtPropBar(float64(ps.conns), float64(maxConns), topBarW),
			styleTopTX.Render(fmt.Sprintf("%-10s", fmtBytes(&out))),
			styleTopRX.Render(fmtBytes(&in))))
	}
	if len(psList) == 0 {
		sb.WriteString("  None\n")
	}
	return sb.String()
}

func renderTopTX(snap *poller.Snapshot) string {
	return renderTopBytes(snap, "Top TX (bytes sent)", true)
}

func renderTopRX(snap *poller.Snapshot) string {
	return renderTopBytes(snap, "Top RX (bytes received)", false)
}

func renderTopBytes(snap *poller.Snapshot, title string, byTX bool) string {
	type bytesEntry struct {
		conn  *model.Connection
		bytes int
	}
	var entries []bytesEntry
	for _, c := range snap.Conns {
		var v *int
		if byTX {
			v = c.BytesSent
		} else {
			v = c.BytesReceived
		}
		if v != nil && *v > 0 {
			entries = append(entries, bytesEntry{conn: c, bytes: *v})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].bytes > entries[j].bytes })
	if len(entries) > 10 {
		entries = entries[:10]
	}
	max := 0
	if len(entries) > 0 {
		max = entries[0].bytes
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" "+title) + "\n")
	sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
		styleTopHdr.Render(fmt.Sprintf("%-5s", "Proto")),
		styleTopHdr.Render(fmt.Sprintf("%-30s", "Peer")),
		styleTopHdr.Render(fmt.Sprintf("%-15s", "Process")),
		styleTopHdr.Render(fmt.Sprintf("%-10s", "Bytes")),
		styleTopHdr.Render("")))
	bytesStyle := styleTopTX
	if !byTX {
		bytesStyle = styleTopRX
	}
	for _, e := range entries {
		proc := "-"
		if e.conn.Process != nil {
			proc = *e.conn.Process
		}
		peer := e.conn.PeerAddr + ":" + e.conn.PeerPort
		b := e.bytes
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
			lipgloss.NewStyle().Foreground(ProtoColor(e.conn.Protocol)).Render(fmt.Sprintf("%-5s", strings.ToUpper(e.conn.Protocol))),
			styleTopAddr.Render(fmt.Sprintf("%-30s", truncate(peer, 30))),
			styleTopProc.Render(fmt.Sprintf("%-15s", truncate(proc, 15))),
			bytesStyle.Render(fmt.Sprintf("%-10s", fmtBytes(&b))),
			fmtPropBar(float64(e.bytes), float64(max), topBarW)))
	}
	if len(entries) == 0 {
		sb.WriteString("  None\n")
	}
	return sb.String()
}

// renderRTT renders avg RTT colored by severity.
func renderRTT(total float64, count, width int) string {
	if count == 0 {
		return styleTopDim.Render(fmt.Sprintf("%-*s", width, "-"))
	}
	avg := total / float64(count)
	val := fmt.Sprintf("%-*s", width, fmt.Sprintf("%.1fms", avg))
	switch {
	case avg > 200:
		return lipgloss.NewStyle().Foreground(colRTTHi).Render(val)
	case avg > 50:
		return lipgloss.NewStyle().Foreground(colRTTMid).Render(val)
	default:
		return lipgloss.NewStyle().Foreground(colRTTOk).Render(val)
	}
}

func renderIssues(warn, crit int) string {
	if warn == 0 && crit == 0 {
		return styleTopDim.Render("·")
	}
	var parts []string
	if crit > 0 {
		parts = append(parts, styleTopWarn.Render(fmt.Sprintf("%d crit", crit)))
	}
	if warn > 0 {
		parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color("#ffa94d")).Render(fmt.Sprintf("%d warn", warn)))
	}
	return strings.Join(parts, " ")
}
