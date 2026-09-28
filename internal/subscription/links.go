package subscription

import (
	"regexp"
	"strings"
)

var nextNodeLink = regexp.MustCompile(`[\t ]+([A-Za-z][A-Za-z0-9+.-]*://)`)

// SplitNodeLinks accepts pasted links separated by newlines or whitespace
// followed by another URI scheme. Spaces in display names and percent-encoded
// URL components are preserved. Parsing/validation remains the caller's job.
func SplitNodeLinks(text string) []string {
	var links []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\r' || r == '\n' }) {
		start := 0
		for _, match := range nextNodeLink.FindAllStringSubmatchIndex(line, -1) {
			if link := strings.TrimSpace(line[start:match[0]]); link != "" {
				links = append(links, link)
			}
			start = match[2]
		}
		if link := strings.TrimSpace(line[start:]); link != "" {
			links = append(links, link)
		}
	}
	return links
}
