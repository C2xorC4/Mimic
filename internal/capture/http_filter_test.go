package capture

import "testing"

func TestClassifyHTTPProbe(t *testing.T) {
	cases := []struct {
		probe string
		name  string
		ok    bool
	}{
		{"GET / HTTP/1.0\r\n\r\n", "http_get", true},
		{"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n", "http_get", true},
		{"GET /iisstart.htm HTTP/1.0\r\n\r\n", "http_get", true},
		{"HEAD / HTTP/1.0\r\n\r\n", "http_head", true},
		{"OPTIONS / HTTP/1.0\r\n\r\n", "http_options", true},
		{"OPTIONS * HTTP/1.0\r\n\r\n", "http_options", true},
		{"POST / HTTP/1.0\r\n\r\n", "http_post", true},
		{"TRACE / HTTP/1.0\r\n\r\n", "http_trace", true},
		{"GET /admin HTTP/1.0\r\n\r\n", "", false},
		{"GET /scripts/iisadmin/ HTTP/1.0\r\n\r\n", "", false},
		{"GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0\r\n\r\n", "", false},
		{"GET /?foo=bar HTTP/1.0\r\n\r\n", "http_get", true},
		{"", "", false},
		{"FOO / HTTP/1.0\r\n\r\n", "", false},
	}

	for _, c := range cases {
		name, ok := classifyHTTPProbe([]byte(c.probe))
		if name != c.name || ok != c.ok {
			t.Errorf("classifyHTTPProbe(%q) = (%q, %v), want (%q, %v)", c.probe, name, ok, c.name, c.ok)
		}
	}
}

func TestIsHTTPServicePort(t *testing.T) {
	for _, port := range []uint16{80, 443, 8080, 8000, 8888} {
		if !isHTTPServicePort(port) {
			t.Errorf("port %d should be HTTP", port)
		}
	}
	if isHTTPServicePort(445) {
		t.Error("port 445 should not be HTTP")
	}
}

func TestTemplateGenerator_HTTPFiltersEnumNoise(t *testing.T) {
	tg := NewTemplateGenerator(t.TempDir(), "http", "test")
	session := &Session{
		Key: FlowKey{ServerPort: 80},
		Exchanges: []Exchange{
			{Probe: []byte("GET /admin HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 404\r\n\r\n")},
			{Probe: []byte("GET /scripts/iisadmin/ HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 404\r\n\r\n")},
			{Probe: []byte("GET / HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\n")},
			{Probe: []byte("OPTIONS / HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\n")},
			{Probe: []byte("HEAD / HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\n")},
		},
	}
	tg.AddSession(session)
	if len(tg.exchanges) != 3 {
		t.Fatalf("want 3 exchanges kept (root GET, OPTIONS, HEAD), got %d", len(tg.exchanges))
	}

	groups := tg.groupExchanges()
	if len(groups) > 10 {
		t.Fatalf("grouped into %d probe buckets, want a small handful", len(groups))
	}
}