package dirs

// Remove paths that are already covered by dedicated recon engines.
// robots.txt is reported by recon, so the directory probe should not emit
// a second, duplicate observation for the same resource.
func init() {
	filtered := wordlist[:0]
	for _, p := range wordlist {
		if p.Path == "/robots.txt" {
			continue
		}
		filtered = append(filtered, p)
	}
	wordlist = filtered
}
