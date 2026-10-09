// Package mask hides secret values in any human-facing output.
package mask

func Secret(s string) string {
	switch {
	case s == "":
		return ""
	case len(s) < 12:
		return "****"
	default:
		return s[:4] + "…" + s[len(s)-4:]
	}
}
