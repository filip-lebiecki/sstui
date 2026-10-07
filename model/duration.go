package model

import "strconv"

// ParseSSDuration parses an ss timer duration into milliseconds. ss prints
// them as a run of <number><unit> parts: "50sec", "6.077sec", "200ms",
// "2min", "1min49sec". ok is false for anything else.
func ParseSSDuration(s string) (ms float64, ok bool) {
	if s == "" {
		return 0, false
	}
	for s != "" {
		i := 0
		for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
			i++
		}
		j := i
		for j < len(s) && s[j] >= 'a' && s[j] <= 'z' {
			j++
		}
		v, err := strconv.ParseFloat(s[:i], 64)
		if err != nil {
			return 0, false
		}
		var mult float64
		switch s[i:j] {
		case "min":
			mult = 60_000
		case "sec", "s":
			mult = 1000
		case "ms":
			mult = 1
		default:
			return 0, false
		}
		ms += v * mult
		s = s[j:]
	}
	return ms, true
}
