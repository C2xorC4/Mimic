package capture

import (
	"bytes"
	"strings"
)

// classifyHTTPProbe buckets an HTTP request into a stable capture group name.
// Returns ("", false) for http-enum style path enumeration probes that would
// otherwise produce one template per dictionary path (~1000+ useless 404s).
func classifyHTTPProbe(probe []byte) (name string, ok bool) {
	if len(probe) < 4 {
		return "", false
	}
	line := probe
	if i := bytes.IndexByte(probe, '\n'); i >= 0 {
		line = probe[:i]
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return "", false
	}

	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return "", false
	}
	method := strings.ToUpper(fields[0])
	target := fields[1]
	path := target
	if i := strings.IndexByte(target, '?'); i >= 0 {
		path = target[:i]
	}

	switch method {
	case "GET":
		if isHTTPRootPath(path) {
			return "http_get", true
		}
		return "", false
	case "HEAD":
		if isHTTPRootPath(path) {
			return "http_head", true
		}
		return "", false
	case "OPTIONS":
		return "http_options", true
	case "POST":
		return "http_post", true
	case "TRACE":
		return "http_trace", true
	case "PUT", "DELETE", "PATCH", "CONNECT":
		return "http_" + strings.ToLower(method), true
	default:
		return "", false
	}
}

func isHTTPRootPath(path string) bool {
	switch path {
	case "/", "/index.html", "/index.htm", "/default.aspx", "/iisstart.htm", "/iisstart.html":
		return true
	default:
		return false
	}
}

func isHTTPServicePort(port uint16) bool {
	switch port {
	case 80, 443, 8080, 8000, 8888:
		return true
	default:
		return false
	}
}