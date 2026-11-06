package main

import (
	"bytes"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed static
var staticFiles embed.FS

// Clients that claim to be Mozilla but are scripting tools. See preferredForm().
var notReallyABrowser = regexp.MustCompile(`(?i)PowerShell|curl|wget|python|java|okhttp|Go-http|libwww|httpie|postman|insomnia|axios|node-fetch`)

var contentTypes = map[string]string{
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".gif":  "image/gif",
	".svg":  "image/svg+xml",
	".ico":  "image/x-icon",
	".txt":  "text/plain; charset=utf-8",
	".css":  "text/css; charset=utf-8",
}

const (
	textPlain = "text/plain; charset=utf-8"
	notFound  = "Sorry! Blue can't find that!"
)

// ── ordered fields ───────────────────────────────────────────────────────────

// fields is an ordered JSON object: the connection's keys come out in the
// order they are described, and the page renders them in the same order.
type field struct {
	Key   string
	Value any
}

type fields []field

func (f fields) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, kv := range f {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := encodeJSON(&b, kv.Key); err != nil {
			return nil, err
		}
		b.WriteByte(':')
		if err := encodeJSON(&b, kv.Value); err != nil {
			return nil, err
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// encodeJSON writes v without HTML escaping: the JSON is not HTML, and a
// header echoed back as < is not the header the client sent.
func encodeJSON(b *bytes.Buffer, v any) error {
	e := json.NewEncoder(b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return err
	}
	b.Truncate(b.Len() - 1) // Encode's newline
	return nil
}

// ── client identity ──────────────────────────────────────────────────────────

// header returns every value of a request header joined, and whether it was
// sent at all — "sent empty" and "not sent" differ in the edge view.
func header(r *http.Request, name string) (string, bool) {
	v, ok := r.Header[http.CanonicalHeaderKey(name)]
	return strings.Join(v, ", "), ok
}

// family reads the address the client actually used: an IPv4 client on a
// dual-stack listener arrives v4-mapped, and prints as plain IPv4.
func family(ip net.IP) string {
	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

type view struct {
	clientIP   string
	protocol   string
	connection fields
}

// 🛑 CF-* headers are only trusted from loopback — i.e. from cloudflared running
// beside us. A direct request carrying a forged CF-Connecting-IP arrives from a
// real remote address and is treated as native, so it cannot spoof its own IP.
// The value must also BE an address: it is echoed and logged as clientIp, so
// anything else would be a free-text field in the access log.
func describe(r *http.Request) view {
	host, port, _ := net.SplitHostPort(r.RemoteAddr)
	remote := net.ParseIP(host)
	if remote.IsLoopback() {
		if cf, _ := header(r, "Cf-Connecting-Ip"); net.ParseIP(cf) != nil {
			return describeEdge(r, net.ParseIP(cf))
		}
	}

	protocol := "http"
	if r.TLS != nil {
		protocol = "https"
	}
	portNum, _ := strconv.Atoi(port)
	conn := fields{{"protocol", protocol}, {"remotePort", portNum}}
	if r.TLS != nil {
		conn = append(conn,
			field{"tlsProtocol", tlsVersionName(r.TLS.Version)},
			field{"cipherName", openSSLName(r.TLS.CipherSuite)},
			field{"cipherStandardName", tls.CipherSuiteName(r.TLS.CipherSuite)},
		)
	}
	conn = append(conn, field{"remoteFamily", family(remote)})
	return view{clientIP: remote.String(), protocol: protocol, connection: conn}
}

func describeEdge(r *http.Request, ip net.IP) view {
	proto, _ := header(r, "X-Forwarded-Proto")
	protocol := "https"
	if strings.ToLower(proto) == "http" {
		protocol = "http"
	}
	conn := fields{{"via", "cloudflare"}, {"protocol", protocol}, {"remoteFamily", family(ip)}}
	// Populated by Cloudflare managed transforms; omitted rather than shown
	// empty when a given header is not configured.
	if v, ok := header(r, "Cf-Ipcountry"); ok {
		conn = append(conn, field{"country", v})
	}
	ray, _ := header(r, "Cf-Ray")
	if parts := strings.Split(ray, "-"); len(parts) > 1 && parts[len(parts)-1] != "" {
		conn = append(conn, field{"colo", parts[len(parts)-1]})
	}
	if ray != "" {
		conn = append(conn, field{"ray", ray})
	}
	if v, ok := header(r, "Cf-Tls-Version"); ok {
		conn = append(conn, field{"tlsVersion", v})
	}
	if v, ok := header(r, "Cf-Tls-Cipher"); ok {
		conn = append(conn, field{"tlsCipher", v})
	}
	return view{clientIP: ip.String(), protocol: protocol, connection: conn}
}

// requestHeaders echoes every header received, names lowercased, in name
// order (net/http does not keep wire order). Host is not in r.Header.
func requestHeaders(r *http.Request) fields {
	names := make([]string, 0, len(r.Header)+1)
	values := map[string]string{"host": r.Host}
	if r.Host != "" {
		names = append(names, "host")
	}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		names = append(names, lk)
		values[lk] = strings.Join(v, ", ")
	}
	sort.Strings(names)
	out := make(fields, len(names))
	for i, k := range names {
		out[i] = field{k, values[k]}
	}
	return out
}

// ── responses ────────────────────────────────────────────────────────────────

// On EVERY response — routes, errors, static and OPTIONS alike.
var commonHeaders = map[string]string{
	// Every response is a point-in-time measurement; caching one is always wrong.
	"Cache-Control":          "no-store, no-cache, must-revalidate, proxy-revalidate",
	"Pragma":                 "no-cache",
	"Expires":                "0",
	"Surrogate-Control":      "no-store",
	"X-Content-Type-Options": "nosniff",
	// Everything here describes the caller and is already known to them, and no
	// credentials or cookies are involved — so "*" gives up nothing and lets
	// browser-based tooling actually read the response.
	"Access-Control-Allow-Origin": "*",
}

func send(w http.ResponseWriter, status int, ctype, body string, extra ...string) int {
	h := w.Header()
	for k, v := range commonHeaders {
		h.Set(k, v)
	}
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	for i := 0; i+1 < len(extra); i += 2 {
		h.Set(extra[i], extra[i+1])
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
	return status
}

// The page has no script and no subresources — only inline style — so nothing
// is allowed but that. A second line behind html/template, not a replacement.
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

func sendPage(w http.ResponseWriter, r *http.Request, v view) int {
	var b bytes.Buffer
	if err := page.Execute(&b, pageData{ClientIP: v.clientIP, Headers: requestHeaders(r), Connection: v.connection}); err != nil {
		panic(err)
	}
	return send(w, http.StatusOK, "text/html; charset=utf-8", b.String(), "Content-Security-Policy", pageCSP)
}

// One JSON body, used by both `/` and `/json`. `timestamp` sits directly under
// clientIp so a caller — an LLM agent especially — can tell a live answer from
// a cached or pasted one; `docs` makes the response self-describing.
func jsonBody(r *http.Request, v view) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	err := e.Encode(struct {
		ClientIP   string `json:"clientIp"`
		Timestamp  string `json:"timestamp"`
		Headers    fields `json:"headers"`
		Connection fields `json:"connection"`
		Docs       string `json:"docs"`
	}{v.clientIP, timestamp(time.Now()), requestHeaders(r), v.connection, docsURL})
	if err != nil {
		panic(err)
	}
	return b.String()
}

// What form should `/` take for this client?
//
// 🛑 THE DEFAULT IS JSON (since 2026-08-02, deliberately breaking the old
// `curl myip.blue` -> bare IP behaviour). Machines are the common caller, so
// they get structured data unless something asks for a page. `/ip` is the
// bare-string endpoint.
//
// The browser test is the ACCEPT HEADER, not the user-agent. Every real browser
// sends `text/html`; curl, wget, python-requests, Go and undici send `*/*` or
// nothing. UA `Mozilla/` is a cheap second opinion, not the primary signal.
func preferredForm(r *http.Request) string {
	accept := strings.ToLower(r.Header.Get("Accept"))
	ua := r.Header.Get("User-Agent")
	asksHTML := strings.Contains(accept, "text/html")

	// An explicit machine ask wins outright.
	if !asksHTML && strings.Contains(accept, "application/json") {
		return "json"
	}
	if !asksHTML && strings.Contains(accept, "text/plain") {
		return "text"
	}
	if asksHTML {
		return "html"
	}
	// UA fallback, needed for exactly one real case: older IE sends an Accept
	// header with NO text/html in it (IE8: "image/gif, image/jpeg, ..., */*").
	// ⚠️ PowerShell's Invoke-WebRequest impersonates Mozilla but wants data,
	// hence the short deny list. Keep it SMALL: Accept is the mechanism.
	if strings.HasPrefix(strings.ToLower(ua), "mozilla/") && !notReallyABrowser.MatchString(ua) {
		return "html"
	}
	return "json"
}

func serveStatic(w http.ResponseWriter, urlPath string) int {
	rel, err := url.PathUnescape(strings.TrimPrefix(urlPath, "/static/"))
	// The files are compiled in, and fs.ValidPath refuses "..", "." and empty
	// elements after decoding — so no request can name anything outside them.
	if err != nil || !fs.ValidPath(rel) {
		return send(w, http.StatusNotFound, textPlain, notFound)
	}
	f, err := staticFiles.Open("static/" + rel)
	if err != nil {
		return send(w, http.StatusNotFound, textPlain, notFound)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return send(w, http.StatusNotFound, textPlain, notFound)
	}
	ctype, ok := contentTypes[strings.ToLower(path.Ext(rel))]
	if !ok {
		ctype = "application/octet-stream"
	}
	h := w.Header()
	for k, v := range commonHeaders {
		h.Set(k, v)
	}
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
	return http.StatusOK
}

// ── routing ──────────────────────────────────────────────────────────────────

// Routes match the ESCAPED path, as sent: "/%69p" is not "/ip", and nothing is
// normalised — "//x" stays a path (RFC 9112 §3.2.1; a scanner's
// "//interactsh.com%2f.." is a 404), and dot segments are not resolved.
// net/http parses origin- and absolute-form and answers anything unparseable
// with its own 400; "*" arrives with the path "*", which has no route.
func route(w http.ResponseWriter, r *http.Request, v view) int {
	if r.Method == http.MethodOptions {
		h := w.Header()
		for k, val := range commonHeaders {
			h.Set(k, val)
		}
		h.Set("Allow", "GET, HEAD, OPTIONS")
		h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Accept, Content-Type")
		h.Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return http.StatusNoContent
	}

	p := r.URL.EscapedPath()
	if p != "" && !strings.HasPrefix(p, "/") {
		return send(w, http.StatusBadRequest, textPlain, "Sorry! Blue can't read that!")
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return send(w, http.StatusMethodNotAllowed, textPlain, notFound, "Allow", "GET, HEAD")
	}

	switch p {
	case "/", "":
		switch preferredForm(r) {
		case "html":
			return sendPage(w, r, v)
		case "text":
			return send(w, http.StatusOK, textPlain, v.clientIP+"\n")
		default:
			return send(w, http.StatusOK, "application/json; charset=utf-8", jsonBody(r, v))
		}
	case "/ip", "/ip/":
		return send(w, http.StatusOK, textPlain, v.clientIP+"\n")
	case "/json", "/json/":
		return send(w, http.StatusOK, "application/json; charset=utf-8", jsonBody(r, v))
	case "/html", "/html/":
		// Forces the page regardless of what the client asked for. Completes the
		// set: /ip, /json and /html each pin one form, and `/` negotiates.
		return sendPage(w, r, v)
	case "/docs", "/docs/", "/llms.txt":
		// Markdown served as text/plain on purpose: it renders readably raw, and a
		// machine gets the whole contract in one cheap request with no HTML to strip.
		return send(w, http.StatusOK, textPlain, docs)
	case "/robots.txt":
		return send(w, http.StatusOK, textPlain, robots)
	case "/.well-known/security.txt":
		return send(w, http.StatusOK, textPlain, securityTxt)
	}
	if strings.HasPrefix(p, "/static/") {
		return serveStatic(w, p)
	}
	return send(w, http.StatusNotFound, textPlain, notFound)
}

// logField escapes the caller-written fields of the access log as nginx does
// (`"`, `\`, control and non-ASCII bytes → \xHH), plus space in the unquoted
// ones, so a User-Agent of `x" 200 1.0ms` cannot forge or shift a field.
// Ordinary values come out byte-identical.
func logField(value string, present, quoted bool) string {
	if !present {
		return "-"
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '"' || c == '\\' || c < 0x20 || c >= 0x7f || (c == ' ' && !quoted) {
			fmt.Fprintf(&b, "\\x%02x", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

type app struct {
	access, errLog *log.Logger
}

// recorder notes whether a response was started, so a panic after the
// headers went out does not try to write a second one.
type recorder struct {
	http.ResponseWriter
	wrote bool
}

func (r *recorder) WriteHeader(code int) {
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

// Static is served through the same handler as everything else so that static
// hits are logged. One access-log line per request, 500s included.
func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	rec := &recorder{ResponseWriter: w}
	v := describe(r)
	status := http.StatusInternalServerError
	defer func() {
		if err := recover(); err != nil {
			if !rec.wrote {
				send(rec, http.StatusInternalServerError, textPlain, "Blue broke!")
			}
			status = http.StatusInternalServerError
			a.errLog.Printf("error %s %s: %v", r.Method, logField(r.RequestURI, true, false), err)
		}
		ua, hasUA := header(r, "User-Agent")
		a.access.Printf("%s %s %s %s \"%s\" %d %.1fms",
			v.clientIP, v.protocol, logField(r.Host, r.Host != "", false), logField(r.RequestURI, true, false),
			logField(ua, hasUA, true), status, float64(time.Since(started).Microseconds())/1000)
	}()
	status = route(rec, r, v)
}
