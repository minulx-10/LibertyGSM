package tlsfrag

import "strings"

// DefaultExcludeHosts mirrors the Python default whitelist: hosts whose servers
// (or fronting security appliances) reject record-fragmented ClientHellos.
// NOTE: on a network that actively SNI-blocks these hosts, excluding them is
// counterproductive -- the plaintext SNI then gets reset. Treat this as an
// editable default, not a hard rule.
var DefaultExcludeHosts = []string{
	"*.nexon.com",
	"*.nexon.co.kr",
	"*.nx.com",
	"*.nexon.io",
	"*.nexon.net",
}

// IsHostExcluded reports whether host matches any pattern in patterns. A pattern
// of the form "*.example.com" matches example.com and any subdomain; a bare
// "example.com" matches the host itself and any subdomain.
func IsHostExcluded(host string, patterns []string) bool {
	if host == "" || host == "<no-sni>" || host == "<empty>" {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[2:]
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == pat || strings.HasSuffix(host, "."+pat) {
			return true
		}
	}
	return false
}
