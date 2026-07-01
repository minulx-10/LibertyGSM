package tlsfrag

import "strings"

// DefaultExcludeHosts is empty: on a DPI network the whole point is to fragment
// everything. Excluding a host sends its plaintext SNI as-is, which the DPI then
// blocks -- the opposite of what we want. Add a host only if fragmenting it
// breaks that specific site's own server.
var DefaultExcludeHosts = []string{}

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
