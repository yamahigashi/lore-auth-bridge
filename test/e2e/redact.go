package e2e

func redactLoreArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i := 0; i < len(out); i++ {
		if out[i] == "--token" && i+1 < len(out) {
			out[i+1] = "<redacted>"
			i++
		}
	}
	return out
}
