// Black-box tests over real sockets, for the things that are easy to
// inadvertently re-break: the path-traversal guard, HTML escaping of
// attacker-controlled headers, the loopback-only trust boundary for CF-*
// headers, the timeouts, the TLS range, and the response contract.
//
// Ported from the Node suite (tag node-final), which this binary passed
// unchanged except where the rewrite changed behaviour — each such test says so.
//
// Run: go test ./...
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var (
	accessLog         syncBuffer
	httpPort, tlsPort int
	edgeAddr          string
)

func testConfig() config {
	return config{
		HTTPAddr: ":0", HTTPSAddr: ":0", EdgeAddr: "127.0.0.1:0",
		// Throwaway self-signed localhost pairs, test-only.
		TLSCert: "testdata/localhost-cert.pem", TLSKey: "testdata/localhost-key.pem",
		TLSRSACert: "testdata/localhost-rsa-cert.pem", TLSRSAKey: "testdata/localhost-rsa-key.pem",
		Access: io.Discard, Errors: io.Discard,
		MaxHTTPConns: maxHTTPConnections, MaxTLSConns: maxTLSConnections, MaxEdgeConns: maxEdgeConnections,
	}
}

func port(a net.Addr) int { return a.(*net.TCPAddr).Port }

func TestMain(m *testing.M) {
	runMainIfAsked()
	cfg := testConfig()
	cfg.Access = &accessLog
	inst, err := start(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	httpPort, tlsPort, edgeAddr = port(inst.HTTPAddr), port(inst.HTTPSAddr), inst.EdgeAddr.String()
	os.Exit(m.Run())
}

var client = &http.Client{Transport: &http.Transport{DisableCompression: true}}

func get(t *testing.T, path string, headers ...string) (*http.Response, string) {
	t.Helper()
	return do(t, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", httpPort, path), headers...)
}

func do(t *testing.T, method, url string, headers ...string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

func getJSON(t *testing.T, path string, headers ...string) map[string]any {
	t.Helper()
	_, body := get(t, path, headers...)
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, body)
	}
	return out
}

func conn(body map[string]any) map[string]any { return body["connection"].(map[string]any) }

// raw writes a request byte for byte — net/http's client would normalise it —
// and returns everything read until the server closes or the deadline passes.
func raw(t *testing.T, addr, payload string, deadline time.Duration) (string, bool) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, payload); err != nil {
		return "", true
	}
	_ = c.SetReadDeadline(time.Now().Add(deadline))
	data, err := io.ReadAll(c)
	var ne net.Error
	return string(data), !(errors.As(err, &ne) && ne.Timeout())
}

func httpAddr() string { return fmt.Sprintf("127.0.0.1:%d", httpPort) }

// status reads the status code off the first response in resp; 0 if none.
func status(resp string) int {
	parts := strings.SplitN(resp, " ", 3)
	if len(parts) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(parts[1])
	return n
}

func rawStatus(t *testing.T, target, method string) int {
	t.Helper()
	resp, _ := raw(t, httpAddr(), method+" "+target+" HTTP/1.1\r\nHost: myip.blue\r\nConnection: close\r\n\r\n", 3*time.Second)
	return status(resp)
}

// A non-loopback address for this host, used to prove that CF-* headers are
// NOT trusted from off-box. Without it that half of the check is untested.
func lanAddress() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	return ""
}

func waitForLog(t *testing.T, substr string) string {
	t.Helper()
	for i := 0; i < 50; i++ {
		for _, l := range strings.Split(accessLog.String(), "\n") {
			if strings.Contains(l, substr) {
				return l
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no access-log line contains %q", substr)
	return ""
}

func TestIPReturnsABareIP(t *testing.T) {
	res, body := get(t, "/ip")
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain") || strings.TrimSpace(body) != "127.0.0.1" {
		t.Fatalf("%d %q %q", res.StatusCode, res.Header.Get("Content-Type"), body)
	}
	if res, _ := get(t, "/ip/"); res.StatusCode != 200 {
		t.Fatal("/ip/ must resolve")
	}
}

func TestRootNegotiation(t *testing.T) {
	cases := []struct{ name, ua, accept, want string }{
		// Changed 2026-08-02: / used to return a bare IP; /ip is the bare endpoint.
		{"curl", "curl/8.7.1", "*/*", "application/json"},
		{"wget", "Wget/1.21.4", "*/*", "application/json"},
		{"python-requests", "python-requests/2.32.3", "*/*", "application/json"},
		{"Go", "Go-http-client/2.0", "*/*", "application/json"},
		{"undici", "undici", "*/*", "application/json"},
		// Invoke-WebRequest claims to be Mozilla; it still wants data.
		{"PowerShell", "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1", "*/*", "application/json"},
		{"asks for html", "", "text/html,application/xhtml+xml,*/*;q=0.8", "text/html"},
		{"Mozilla UA, no html in Accept", "Mozilla/5.0 Chrome/120", "*/*", "text/html"},
		{"json beats a browser UA", "Mozilla/5.0 Chrome/120", "application/json", "application/json"},
		{"text/plain escape hatch", "curl/8.7.1", "text/plain", "text/plain"},
		{"html wins over text/plain in one list", "", "text/html,text/plain;q=0.9,*/*;q=0.8", "text/html"},
		{"Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "text/html"},
		{"Firefox", "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8", "text/html"},
		{"Safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html"},
		{"Edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "text/html,application/xhtml+xml,*/*;q=0.8", "text/html"},
		{"IE11", "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko", "text/html, application/xhtml+xml, image/jxr, */*", "text/html"},
		// IE8 sends NO text/html at all — only the Mozilla/ fallback saves it.
		{"IE8", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)", "image/gif, image/jpeg, image/pjpeg, */*", "text/html"},
		{"MobileSafari", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "text/html,application/xhtml+xml,*/*;q=0.8", "text/html"},
	}
	for _, c := range cases {
		res, body := get(t, "/", "User-Agent", c.ua, "Accept", c.accept)
		if !strings.HasPrefix(res.Header.Get("Content-Type"), c.want) {
			t.Errorf("%s: got %s, want %s", c.name, res.Header.Get("Content-Type"), c.want)
		}
		switch c.want {
		case "application/json":
			var b map[string]any
			if json.Unmarshal([]byte(body), &b) != nil || b["clientIp"] != "127.0.0.1" {
				t.Errorf("%s: bad JSON %q", c.name, body)
			}
		case "text/plain":
			if strings.TrimSpace(body) != "127.0.0.1" {
				t.Errorf("%s: %q", c.name, body)
			}
		case "text/html":
			if !strings.Contains(body, "Your public IP address") {
				t.Errorf("%s: not the page", c.name)
			}
		}
	}
}

func TestHTMLForcesThePage(t *testing.T) {
	for _, p := range []string{"/html", "/html/"} {
		res, body := get(t, p, "User-Agent", "curl/8.7.1", "Accept", "application/json")
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") || !strings.Contains(body, "Your public IP address") {
			t.Errorf("%s: %d %s", p, res.StatusCode, res.Header.Get("Content-Type"))
		}
	}
}

func TestDocs(t *testing.T) {
	res, a := get(t, "/docs")
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain") || !strings.HasPrefix(a, "# myip.blue") {
		t.Fatalf("%d %q", res.StatusCode, a[:20])
	}
	for _, p := range []string{"/docs/", "/llms.txt"} {
		if _, b := get(t, p); b != a {
			t.Errorf("%s must match /docs byte for byte", p)
		}
	}
	for _, ep := range []string{"/ip", "/json", "/html", "/docs", "/llms.txt", "/static/"} {
		if !strings.Contains(a, ep) {
			t.Errorf("docs should mention %s", ep)
		}
	}
	if strings.Contains(a, "/test/") {
		t.Error("docs must not advertise the removed SSRF endpoint")
	}
}

func TestJSONReportsTheConnection(t *testing.T) {
	b := getJSON(t, "/json")
	c := conn(b)
	if b["clientIp"] != "127.0.0.1" || c["protocol"] != "http" || c["remoteFamily"] != "IPv4" {
		t.Fatal(b)
	}
	if _, ok := c["remotePort"].(float64); !ok {
		t.Fatalf("remotePort must be a number: %v", c["remotePort"])
	}
}

func TestJSONTimestampAndKeyOrder(t *testing.T) {
	before := time.Now()
	_, body := get(t, "/json")
	var b map[string]any
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatal(err)
	}
	ts, err := time.Parse(time.RFC3339, b["timestamp"].(string))
	if err != nil || ts.Before(before.Add(-5*time.Second)) || ts.After(time.Now().Add(5*time.Second)) {
		t.Fatalf("timestamp must be current: %v %v", b["timestamp"], err)
	}
	// Key ORDER matters: timestamp directly below clientIp, docs last.
	var keys []string
	dec := json.NewDecoder(strings.NewReader(body))
	dec.Token()
	for dec.More() {
		k, _ := dec.Token()
		keys = append(keys, k.(string))
		var skip json.RawMessage
		dec.Decode(&skip)
	}
	if strings.Join(keys, ",") != "clientIp,timestamp,headers,connection,docs" || b["docs"] != "https://myip.blue/docs" {
		t.Fatalf("keys %v docs %v", keys, b["docs"])
	}
	time.Sleep(5 * time.Millisecond)
	if getJSON(t, "/json")["timestamp"] == b["timestamp"] {
		t.Fatal("timestamp must change between requests")
	}
}

// TestMain re-runs this binary as the real server when MYIP_RUN_MAIN is set,
// so main() itself — env config, startup, signal handling — runs under test.
func runMainIfAsked() {
	if os.Getenv("MYIP_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
}

func TestMainServesWithEnvConfigAndExitsCleanlyOnSIGTERM(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := strconv.Itoa(port(ln.Addr()))
	ln.Close()
	// Tokyo is +9: the timestamp is advertised as a clock reference, so UTC
	// must be a guarantee, not a consequence of the host running UTC.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "MYIP_RUN_MAIN=1", "TZ=Asia/Tokyo", "HTTP_PORT="+p, "TLS_CERT=/nonexistent")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var ts string
	for i := 0; i < 50 && ts == ""; i++ {
		time.Sleep(50 * time.Millisecond)
		res, err := http.Get("http://127.0.0.1:" + p + "/json")
		if err != nil {
			continue
		}
		var b map[string]any
		json.NewDecoder(res.Body).Decode(&b)
		res.Body.Close()
		ts, _ = b["timestamp"].(string)
	}
	parsed, _ := time.Parse(time.RFC3339, ts)
	if !strings.HasSuffix(ts, "Z") || time.Since(parsed).Abs() > time.Minute {
		t.Errorf("timestamp must be UTC under TZ=Asia/Tokyo: %q", ts)
	}
	if healthcheck(p) != 0 {
		t.Error("healthcheck must pass against the env-configured server")
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SIGTERM must exit 0: %v", err)
		}
	case <-time.After(6 * time.Second):
		cmd.Process.Kill()
		t.Fatal("did not exit on SIGTERM")
	}
}

func TestPage(t *testing.T) {
	res, body := get(t, "/", "User-Agent", "Mozilla/5.0 Chrome/120")
	if regexp.MustCompile(`(?i)timestamp`).MatchString(body) {
		t.Error("the page must not carry the timestamp (json-only by design)")
	}
	for _, href := range []string{"https://myip.blue/", "https://v4.myip.blue/", "https://v6.myip.blue/", "https://myip.blue/json", "https://myip.blue/ip", "https://cf.myip.blue/"} {
		if !strings.Contains(body, `href="`+href+`"`) {
			t.Errorf("missing link: %s", href)
		}
	}
	// The anchors must sit INSIDE span.code, or they lose the monospace styling.
	if !strings.Contains(body, `<span class="code"><a href="https://myip.blue/">myip.blue</a></span>`) ||
		!regexp.MustCompile(`\.code a \{[^}]*text-decoration: none`).MatchString(body) {
		t.Error("usage links lost the code styling")
	}
	const csp = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
	if res.Header.Get("Content-Security-Policy") != csp {
		t.Errorf("CSP: %q", res.Header.Get("Content-Security-Policy"))
	}
	if res, _ := get(t, "/html"); res.Header.Get("Content-Security-Policy") != csp {
		t.Error("/html must carry the CSP too")
	}
}

func TestHeaderValuesAreEscapedInThePage(t *testing.T) {
	_, body := get(t, "/", "User-Agent", "Mozilla/5.0", "X-Evil", "<script>alert(1)</script>")
	if !strings.Contains(body, "&lt;script&gt;") || strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("payload must be escaped")
	}
}

func TestUnknownPathsAndMethods(t *testing.T) {
	res, body := get(t, "/nope")
	if res.StatusCode != 404 || body != "Sorry! Blue can't find that!" {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
	res, _ = do(t, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/", httpPort))
	if res.StatusCode != 405 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain; charset=utf-8") || res.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST: %d %v", res.StatusCode, res.Header)
	}
}

func TestRequestTargets(t *testing.T) {
	// RFC 9112 §3.2.1: origin-form is 1*( "/" segment ) and a segment may be
	// empty, so //host is a path (the scanner 500, 2026-11).
	for _, c := range []struct {
		target, method string
		want           int
	}{
		{"//interactsh.com%2f..", "GET", 404},
		{"//example.com/ip", "GET", 404},
		{"/ip?x=//interactsh.com%2f..", "GET", 200},
		// §3.2.2: a server MUST accept absolute-form.
		{"http://myip.blue/ip", "GET", 200},
		{"http://[bad/", "GET", 400},
		{"*", "GET", 400},
		{"*", "OPTIONS", 204},
		// The escaped path is matched as sent: no decoding, no normalising.
		{"/%69p", "GET", 404},
		{"/json/../ip", "GET", 404},
	} {
		if got := rawStatus(t, c.target, c.method); got != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.target, got, c.want)
		}
	}
}

func TestHostRules(t *testing.T) {
	// RFC 9112 §3.2: no Host on HTTP/1.1, or two, MUST be a 400. net/http
	// answers these itself; they never reach route() or the access log (Node's
	// clientError override logged them — not carried over).
	for _, req := range []string{
		"GET /ip HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: close\r\n\r\n",
		"GET /ip HTTP/1.1\r\nConnection: close\r\n\r\n",
		"GET /ip HTTP/1.1\r\nHost: a b\r\nConnection: close\r\n\r\n",
		"GET /ip HTTP/1.1\r\nBad Header\r\n\r\n",
	} {
		if resp, _ := raw(t, httpAddr(), req, 3*time.Second); status(resp) != 400 {
			t.Errorf("%q: %q", req, resp)
		}
	}
	// HTTP/1.0 has no Host requirement.
	if resp, _ := raw(t, httpAddr(), "GET /ip HTTP/1.0\r\n\r\n", 3*time.Second); status(resp) != 200 {
		t.Errorf("HTTP/1.0 without Host: %q", resp)
	}
}

func TestUserAgentCannotForgeAccessLogFields(t *testing.T) {
	marker := fmt.Sprintf("forge-%d", time.Now().UnixNano())
	raw(t, httpAddr(), "GET /ip HTTP/1.1\r\nHost: myip.blue\r\nUser-Agent: "+marker+"\" 200 1.0ms\\\r\nConnection: close\r\n\r\n", 3*time.Second)
	line := waitForLog(t, marker)
	if !regexp.MustCompile(` http myip\.blue /ip "forge-\d+\\x22 200 1\.0ms\\x5c" 200 [\d.]+ms$`).MatchString(line) {
		t.Fatalf("forged line: %s", line)
	}
	// A plain browser UA keeps its spaces: escaping must not change ordinary lines.
	get(t, "/ip", "User-Agent", "Mozilla/5.0 (X11) "+marker+"-plain")
	if line := waitForLog(t, marker+"-plain"); !strings.Contains(line, `"Mozilla/5.0 (X11) `+marker+`-plain" 200`) {
		t.Fatalf("plain line changed: %s", line)
	}
}

func TestAccessLogLineFormat(t *testing.T) {
	marker := fmt.Sprintf("fmt-%d", time.Now().UnixNano())
	get(t, "/static/blue.jpg?"+marker, "User-Agent", "curl/8.7.1")
	line := waitForLog(t, marker)
	// <ISO8601> - <ip> <proto> <host> <url> "<ua>" <status> <ms>, static included.
	want := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z - 127\.0\.0\.1 http 127\.0\.0\.1:\d+ /static/blue\.jpg\?fmt-\d+ "curl/8\.7\.1" 200 \d+\.\dms$`)
	if !want.MatchString(line) {
		t.Fatalf("line: %s", line)
	}
}

func TestStaticFiles(t *testing.T) {
	res, _ := get(t, "/static/blue.jpg")
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/jpeg" {
		t.Fatalf("%d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
}

func TestPathTraversalOutOfStaticIsRefused(t *testing.T) {
	for _, p := range []string{
		"/static/../go.mod",
		"/static/../../etc/passwd",
		"/static/%2e%2e/go.mod",
		"/static/..%2fgo.mod",
		"/static/....//go.mod",
		"/static/%2fetc%2fpasswd",
		"/static/",
		"/static/.",
	} {
		resp, _ := raw(t, httpAddr(), "GET "+p+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 3*time.Second)
		if status(resp) != 404 || regexp.MustCompile(`module |root:`).MatchString(resp) {
			t.Errorf("%s was served: %.80q", p, resp)
		}
	}
}

func TestPathsAreCaseSensitive(t *testing.T) {
	// Deliberate (Drew, 2026-08-02): an undocumented leniency becomes a contract
	// as soon as something depends on it, and then it cannot be removed.
	for _, p := range []string{"/JSON", "/Json", "/IP", "/Docs", "/LLMS.TXT", "/HTML", "/Robots.txt", "/.well-known/Security.txt", "/STATIC/blue.jpg"} {
		if res, _ := get(t, p); res.StatusCode != 404 {
			t.Errorf("%s must NOT resolve", p)
		}
	}
	for _, p := range []string{"/json", "/ip", "/docs", "/llms.txt", "/html", "/robots.txt", "/.well-known/security.txt", "/static/blue.jpg"} {
		if res, _ := get(t, p); res.StatusCode != 200 {
			t.Errorf("%s: %d", p, res.StatusCode)
		}
	}
}

func TestContentTypesMatchBodies(t *testing.T) {
	for _, c := range []struct{ path, accept, want string }{
		{"/", "", "application/json; charset=utf-8"},
		{"/", "text/plain", "text/plain; charset=utf-8"},
		{"/", "text/html", "text/html; charset=utf-8"},
		{"/ip", "", "text/plain; charset=utf-8"},
		{"/json", "", "application/json; charset=utf-8"},
		{"/html", "", "text/html; charset=utf-8"},
		{"/docs", "", "text/plain; charset=utf-8"},
		{"/llms.txt", "", "text/plain; charset=utf-8"},
		{"/static/blue.jpg", "", "image/jpeg"}, // binary declares no charset
		{"/nope", "", "text/plain; charset=utf-8"},
	} {
		if res, _ := get(t, c.path, "Accept", c.accept); res.Header.Get("Content-Type") != c.want {
			t.Errorf("%s %q: %s", c.path, c.accept, res.Header.Get("Content-Type"))
		}
	}
	if _, b := get(t, "/html"); !strings.HasPrefix(b, "<!DOCTYPE html>") {
		t.Error("/html is not HTML")
	}
}

func TestCommonHeadersOnEveryResponse(t *testing.T) {
	for _, p := range []string{"/", "/ip", "/json", "/html", "/docs", "/llms.txt", "/robots.txt", "/.well-known/security.txt", "/nope", "/static/blue.jpg"} {
		res, _ := get(t, p)
		if res.Header.Get("Access-Control-Allow-Origin") != "*" || !strings.Contains(res.Header.Get("Cache-Control"), "no-store") || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: %v", p, res.Header)
		}
	}
	res, _ := do(t, http.MethodOptions, fmt.Sprintf("http://127.0.0.1:%d/ip", httpPort))
	if res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Origin") != "*" || !strings.Contains(res.Header.Get("Access-Control-Allow-Methods"), "GET") ||
		res.Header.Get("Allow") != "GET, HEAD, OPTIONS" || !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
		t.Errorf("OPTIONS: %d %v", res.StatusCode, res.Header)
	}
}

func TestRobotsAndSecurityTxt(t *testing.T) {
	_, robots := get(t, "/robots.txt")
	if !strings.Contains(robots, "User-agent: *") || !strings.Contains(robots, "Allow: /") || !strings.Contains(robots, "llms.txt") || regexp.MustCompile(`(?m)^Disallow: /\s*$`).MatchString(robots) {
		t.Errorf("robots.txt: %q", robots)
	}
	_, sec := get(t, "/.well-known/security.txt")
	if !regexp.MustCompile(`(?m)^Contact: mailto:.+@.+$`).MatchString(sec) {
		t.Error("Contact is required (RFC 9116)")
	}
	m := regexp.MustCompile(`(?m)^Expires: (.+)$`).FindStringSubmatch(sec)
	if m == nil {
		t.Fatal("Expires is required (RFC 9116)")
	}
	// It keeps serving a 200 forever once stale and nothing else notices: fail the build.
	if exp, err := time.Parse(time.RFC3339, m[1]); err != nil || !exp.After(time.Now()) {
		t.Fatalf("security.txt Expires has passed (%s) — renew it here and on the edge zones", m[1])
	}
}

func TestEdgeHeaders(t *testing.T) {
	// 🛑 Honoured from loopback (the tunnel path)...
	b := getJSON(t, "/json", "Cf-Connecting-Ip", "203.0.113.7", "Cf-Ipcountry", "US", "Cf-Ray", "abc123-SJC")
	c := conn(b)
	if b["clientIp"] != "203.0.113.7" || c["via"] != "cloudflare" || c["country"] != "US" || c["colo"] != "SJC" {
		t.Fatal(b)
	}
	// ...but must be well-formed to be believed: no free text in the log or JSON.
	b = getJSON(t, "/json", "Cf-Connecting-Ip", `6.6.6.6 https x /admin "curl" 200 0.1ms`)
	if b["clientIp"] != "127.0.0.1" || conn(b)["via"] != nil {
		t.Fatal("a non-address CF-Connecting-IP is not an edge request")
	}
	b = getJSON(t, "/json", "Cf-Connecting-Ip", "203.0.113.9", "X-Forwarded-Proto", `HTTPS x" 999`, "Cf-Ray", "abc-")
	c = conn(b)
	if b["clientIp"] != "203.0.113.9" || c["protocol"] != "https" {
		t.Fatal("only http/https are reported", b)
	}
	if _, ok := c["colo"]; ok {
		t.Fatal("an empty colo is omitted, not reported empty")
	}
}

func TestEdgeHeadersIgnoredOffBox(t *testing.T) {
	lan := lanAddress()
	if lan == "" {
		t.Skip("no non-loopback interface available")
	}
	_, body := do(t, http.MethodGet, fmt.Sprintf("http://%s:%d/json", lan, httpPort), "Cf-Connecting-Ip", "203.0.113.7")
	var b map[string]any
	json.Unmarshal([]byte(body), &b)
	if b["clientIp"] == "203.0.113.7" || conn(b)["via"] != nil {
		t.Fatal("🛑 a spoofed CF header from off-box must not set clientIp")
	}
}

func TestEdgeListenerIsLoopbackOnly(t *testing.T) {
	_, body := do(t, http.MethodGet, "http://"+edgeAddr+"/json", "Cf-Connecting-Ip", "203.0.113.7")
	var b map[string]any
	json.Unmarshal([]byte(body), &b)
	if b["clientIp"] != "203.0.113.7" || conn(b)["via"] != "cloudflare" {
		t.Fatal(b)
	}
	lan := lanAddress()
	if lan == "" {
		t.Skip("no non-loopback address on this host")
	}
	_, p, _ := net.SplitHostPort(edgeAddr)
	if c, err := net.DialTimeout("tcp", net.JoinHostPort(lan, p), time.Second); err == nil {
		c.Close()
		t.Fatalf("edge port must not be reachable on %s", lan)
	}
}

// ── timeouts and floods ─────────────────────────────────────────────────────

func TestSlowRequestsAreCutOff(t *testing.T) {
	t.Parallel()
	// A partial request line, then nothing. net/http closes it at
	// ReadHeaderTimeout without an answer (Node sent a 408 — not carried over).
	started := time.Now()
	_, closed := raw(t, httpAddr(), "GET /ip HTTP/1.1\r\n", 8*time.Second)
	if !closed || time.Since(started) > 6*time.Second {
		t.Fatalf("held %v", time.Since(started))
	}
}

func TestDrippedHeadersAreCutOff(t *testing.T) {
	t.Parallel()
	// One header a second keeps the socket busy; the deadline is absolute.
	c, err := net.Dial("tcp", httpAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	started := time.Now()
	io.WriteString(c, "GET /ip HTTP/1.1\r\nHost: x\r\n")
	for time.Since(started) < 9*time.Second {
		if _, err := io.WriteString(c, "X-Drip: 1\r\n"); err != nil {
			break
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(make([]byte, 1)); err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				break // closed by the server
			}
		}
	}
	if time.Since(started) > 7*time.Second {
		t.Fatalf("held %v", time.Since(started))
	}
}

func TestSilentTLSClientIsCutOff(t *testing.T) {
	t.Parallel()
	// net/http runs the handshake under the smallest read/write timeout; with
	// none set it would wait forever.
	started := time.Now()
	_, closed := raw(t, fmt.Sprintf("127.0.0.1:%d", tlsPort), "", 8*time.Second)
	if !closed || time.Since(started) > 6*time.Second {
		t.Fatalf("silent TLS socket held %v", time.Since(started))
	}
}

func TestIdleKeepAliveIsClosed(t *testing.T) {
	t.Parallel()
	c, err := net.Dial("tcp", httpAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /ip HTTP/1.1\r\nHost: x\r\n\r\n")
	started := time.Now()
	c.SetReadDeadline(time.Now().Add(9 * time.Second))
	io.ReadAll(c)
	if time.Since(started) > 7*time.Second {
		t.Fatalf("idle keep-alive held %v", time.Since(started))
	}
}

func TestConnectionCapsHoldTheExcessBack(t *testing.T) {
	t.Parallel()
	// 🛑 Each idle connection costs memory; under Node ~1,500 TLS ones
	// OOM-killed the container (2026-11-06). A full listener accepts nothing
	// more: a connection past the cap is not served until a slot frees.
	cfg := testConfig()
	cfg.EdgeAddr = ""
	cfg.MaxHTTPConns, cfg.MaxTLSConns = 5, 5
	inst, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.shutdown(t.Context())
	tlsAddr := fmt.Sprintf("127.0.0.1:%d", port(inst.HTTPSAddr))
	handshake := func() (*tls.Conn, error) {
		raw, err := net.Dial("tcp", tlsAddr)
		if err != nil {
			return nil, err
		}
		raw.SetDeadline(time.Now().Add(time.Second))
		c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
		if err := c.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		raw.SetDeadline(time.Time{})
		return c, nil
	}
	var open []*tls.Conn
	for i := 0; i < 5; i++ {
		c, err := handshake()
		if err != nil {
			t.Fatalf("connection %d under the cap must open: %v", i, err)
		}
		open = append(open, c)
	}
	if c, err := handshake(); err == nil {
		c.Close()
		t.Fatal("a connection past the cap must not be served")
	}
	open[0].Close()
	time.Sleep(100 * time.Millisecond)
	c, err := handshake()
	if err != nil {
		t.Fatalf("a freed slot must be usable: %v", err)
	}
	c.Close()
	for _, c := range open[1:] {
		c.Close()
	}
}

func TestClientErrorsAnswerOrCloseAndTheServerSurvives(t *testing.T) {
	// Oversized headers → 431.
	if resp, _ := raw(t, httpAddr(), "GET /ip HTTP/1.1\r\nHost: x\r\nX-Big: "+strings.Repeat("a", 64<<10)+"\r\n\r\n", 3*time.Second); status(resp) != 431 {
		t.Errorf("oversized: %.60q", resp)
	}
	// A malformed request AFTER a good one on the same keep-alive socket: the
	// good one is answered first, then the stream closes. (net/http answers the
	// bad one with a 400 where Node stayed silent — not carried over.)
	resp, closed := raw(t, httpAddr(), "GET /ip HTTP/1.1\r\nHost: x\r\n\r\nGET /ip HTTP/1.1\r\nBad Header\r\n\r\n", 3*time.Second)
	if !strings.HasPrefix(resp, "HTTP/1.1 200 ") || !closed {
		t.Errorf("pipelined: %q", resp)
	}
	// Plain HTTP / junk at the TLS port → no HTTP answer in clear, no crash.
	tlsAddr := fmt.Sprintf("127.0.0.1:%d", tlsPort)
	for _, junk := range []string{"\x16\x03\x01\x00\x05junk!", "\x16\x03\x01"} {
		if resp, _ := raw(t, tlsAddr, junk, 3*time.Second); strings.HasPrefix(resp, "HTTP/") {
			t.Errorf("junk at TLS: %q", resp)
		}
	}
	// A client that resets mid-request, on both listeners.
	for _, a := range []string{httpAddr(), tlsAddr} {
		c, err := net.Dial("tcp", a)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "GET /ip HTTP/1.1\r\nHost: x\r\nX-Half:")
		c.(*net.TCPConn).SetLinger(0)
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if res, _ := get(t, "/ip"); res.StatusCode != 200 {
		t.Fatal("server must survive every one of these")
	}
}

func TestHandlerPanicIsA500AndLogged(t *testing.T) {
	var errs, access syncBuffer
	a := &app{access: newLogger(&access), errLog: newLogger(&errs)}
	w := &panicWriter{header: http.Header{}}
	req, _ := http.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr, req.RequestURI = "192.0.2.1:1234", "/ip"
	a.ServeHTTP(w, req)
	if w.status != 500 || w.body.String() != "Blue broke!" {
		t.Fatalf("%d %q", w.status, w.body.String())
	}
	if !strings.Contains(errs.String(), "error GET /ip: boom") || !strings.Contains(access.String(), " - 192.0.2.1 http - /ip \"-\" 500 ") {
		t.Fatalf("errors %q access %q", errs.String(), access.String())
	}
}

// panicWriter panics the first time the route touches it — before anything is
// written, as a broken route would — then records the 500 written instead.
type panicWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	failed bool
}

func (p *panicWriter) Header() http.Header {
	if !p.failed {
		p.failed = true
		panic("boom")
	}
	return p.header
}
func (p *panicWriter) WriteHeader(code int)        { p.status = code }
func (p *panicWriter) Write(b []byte) (int, error) { return p.body.Write(b) }

// ── TLS ──────────────────────────────────────────────────────────────────────

func tlsJSON(t *testing.T, cfg *tls.Config) (map[string]any, *tls.ConnectionState) {
	t.Helper()
	c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort), cfg)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer c.Close()
	io.WriteString(c, "GET /json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var b map[string]any
	if err := json.NewDecoder(res.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	st := c.ConnectionState()
	return b, &st
}

func TestEverySuiteGoImplementsNegotiatesAndIsReported(t *testing.T) {
	// 🛑 As low as Go goes, on purpose: an old client must see what it
	// negotiated. Every suite at every version it exists for, against a
	// server holding an ECDSA and an RSA certificate.
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		for _, v := range versions {
			if !supports(s, v) {
				continue
			}
			t.Run(tlsVersionName(v)+"/"+s.Name, func(t *testing.T) {
				b, st := tlsJSON(t, &tls.Config{InsecureSkipVerify: true, MinVersion: v, MaxVersion: v, CipherSuites: []uint16{s.ID}})
				c := conn(b)
				if st.CipherSuite != s.ID || c["cipherStandardName"] != s.Name || c["cipherName"] != openSSLNames[s.ID] || c["tlsProtocol"] != tlsVersionName(v) || c["protocol"] != "https" {
					t.Fatalf("negotiated %s; reported %v", tls.CipherSuiteName(st.CipherSuite), c)
				}
			})
		}
	}
	b, st := tlsJSON(t, &tls.Config{InsecureSkipVerify: true})
	if st.Version != tls.VersionTLS13 || conn(b)["tlsProtocol"] != "TLSv1.3" || conn(b)["cipherName"] != tls.CipherSuiteName(st.CipherSuite) {
		t.Fatalf("TLS 1.3: %v", conn(b))
	}
}

func supports(s *tls.CipherSuite, v uint16) bool {
	for _, x := range s.SupportedVersions {
		if x == v {
			return true
		}
	}
	return false
}

func TestEverySuiteHasAnOpenSSLName(t *testing.T) {
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if _, ok := openSSLNames[s.ID]; !ok {
			t.Errorf("%s has no OpenSSL name", s.Name)
		}
	}
}

func TestOpenSSLNamesMatchOpenSSL(t *testing.T) {
	out, err := exec.Command("openssl", "ciphers", "-stdname", "ALL:COMPLEMENTOFALL:@SECLEVEL=0").Output()
	if err != nil {
		t.Skipf("no openssl with -stdname here: %v", err)
	}
	// "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 - ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH ..."
	known := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[1] == "-" {
			known[f[0]] = f[2]
		}
	}
	checked := 0
	for id, name := range openSSLNames {
		iana := tls.CipherSuiteName(id)
		if want, ok := known[iana]; ok {
			checked++
			if name != want {
				t.Errorf("%s: table says %s, openssl says %s", iana, name, want)
			}
		}
	}
	// A build without RC4 still knows the rest; zero matches means a parse failure.
	if checked < 15 {
		t.Fatalf("only %d suites checked against openssl", checked)
	}
}

func TestHTTP2IsNotNegotiated(t *testing.T) {
	_, st := tlsJSON(t, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if st.NegotiatedProtocol == "h2" {
		t.Fatal("h2 negotiated; HTTP/1.1 only until enabling it is its own change")
	}
}

func TestOldClientsGetTheRSACertificate(t *testing.T) {
	// RSA key exchange needs an RSA certificate; a modern client keeps ECDSA.
	_, st := tlsJSON(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}})
	if fmt.Sprintf("%T", st.PeerCertificates[0].PublicKey) != "*rsa.PublicKey" {
		t.Fatalf("RSA-only client got a %T key", st.PeerCertificates[0].PublicKey)
	}
	_, st = tlsJSON(t, &tls.Config{InsecureSkipVerify: true})
	if fmt.Sprintf("%T", st.PeerCertificates[0].PublicKey) != "*ecdsa.PublicKey" {
		t.Fatalf("modern client got a %T key", st.PeerCertificates[0].PublicKey)
	}
}

func TestWithoutAnRSACertRSAOnlyClientsFailAndTheRestWork(t *testing.T) {
	cfg := testConfig()
	cfg.EdgeAddr, cfg.TLSRSACert, cfg.TLSRSAKey = "", "", ""
	inst, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.shutdown(t.Context())
	addr := fmt.Sprintf("127.0.0.1:%d", port(inst.HTTPSAddr))
	if c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}, MaxVersion: tls.VersionTLS12}); err == nil {
		c.Close()
		t.Fatal("an RSA-kex suite cannot work with only an ECDSA certificate")
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10})
	if err != nil {
		t.Fatalf("TLS 1.0 with ECDHE_ECDSA must still work: %v", err)
	}
	c.Close()
}

func TestTLSIsOptional(t *testing.T) {
	cfg := testConfig()
	cfg.EdgeAddr, cfg.TLSCert = "", "/nonexistent"
	var errs syncBuffer
	cfg.Errors = &errs
	inst, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.shutdown(t.Context())
	if inst.HTTPSAddr != nil || !strings.Contains(errs.String(), "TLS disabled") {
		t.Fatalf("unreadable cert must mean HTTP only, with a warning: %q", errs.String())
	}
}

func TestHealthcheck(t *testing.T) {
	if healthcheck(strconv.Itoa(httpPort)) != 0 {
		t.Fatal("must pass against the running server")
	}
	// Nothing listening here → must fail, or the healthcheck is decorative.
	if healthcheck("1") == 0 {
		t.Fatal("must fail when nothing is listening")
	}
}
