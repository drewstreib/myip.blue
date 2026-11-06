// myip.blue — a connection diagnostic service.
//
// Standard library plus golang.org/x/net/netutil. See CLAUDE.md for the
// functional contract this must preserve.
//
// TWO VIEWS OF THE SAME SERVICE, and the difference is the whole point:
//   - NATIVE — myip.blue / v4. / v6. terminate TLS here, so the real client
//     socket is visible: source port, negotiated cipher, TLS version.
//     🛑 This path is the CONTROL: keep it the cleanest possible network
//     route, no proxy and no CDN, or it stops being a reference measurement.
//   - EDGE — cf.myip.blue arrives via a cloudflared tunnel on loopback. The
//     socket is then cloudflared's, not the client's, so client facts come
//     from CF-* headers and the edge's own view is reported.
//
// Comparing the two is the diagnostic.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
)

// 🛑 Connection caps — the only bound on a connection FLOOD. Keep-alive that
// re-requests inside the idle timeout trips no timeout, and under Node ~1,500
// idle TLS connections OOM-killed the container (2026-11-06), taking down
// every front door. A full listener stops accepting: further connections wait
// in the kernel backlog until a slot frees. Telling one abusive source from
// everyone else is a per-source limit, which belongs in the host firewall.
const (
	maxHTTPConnections = 2000
	maxTLSConnections  = 1000
	maxEdgeConnections = 500 // cloudflared only; it pools a handful
)

type config struct {
	HTTPAddr  string // ":80"
	HTTPSAddr string // ":443"; empty = no TLS listener
	EdgeAddr  string // "127.0.0.1:8080"; empty = no edge listener
	// The primary pair, and an optional RSA pair: the legacy suites that use
	// RSA key exchange or ECDHE_RSA need an RSA certificate, and Go serves
	// each client the first certificate it supports.
	TLSCert, TLSKey       string
	TLSRSACert, TLSRSAKey string
	Access, Errors        io.Writer
	// Per-listener connection caps; the constants above in production.
	MaxHTTPConns, MaxTLSConns, MaxEdgeConns int
}

func configFromEnv() config {
	env := func(k, def string) string {
		if v, ok := os.LookupEnv(k); ok {
			return v
		}
		return def
	}
	cfg := config{
		HTTPAddr:   ":" + env("HTTP_PORT", "80"),
		HTTPSAddr:  ":" + env("HTTPS_PORT", "443"),
		TLSCert:    env("TLS_CERT", "/chain.pem"),
		TLSKey:     env("TLS_KEY", "/key.pem"),
		TLSRSACert: env("TLS_RSA_CERT", ""),
		TLSRSAKey:  env("TLS_RSA_KEY", ""),
		Access:     os.Stdout,
		Errors:     os.Stderr,

		MaxHTTPConns: maxHTTPConnections,
		MaxTLSConns:  maxTLSConnections,
		MaxEdgeConns: maxEdgeConnections,
	}
	if p := env("EDGE_PORT", "0"); p != "0" && p != "" {
		cfg.EdgeAddr = "127.0.0.1:" + p
	}
	return cfg
}

// stamped prefixes every line with the access log's timestamp, so the two
// streams read the same. log.Logger calls Write once per line.
type stamped struct{ w io.Writer }

func (s stamped) Write(p []byte) (int, error) {
	if _, err := fmt.Fprintf(s.w, "%s - %s", timestamp(time.Now()), p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func newLogger(w io.Writer) *log.Logger { return log.New(stamped{w}, "", 0) }

func timestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// 🛑 Aggressive on purpose. This service answers in well under a millisecond,
// so 5s is already catastrophic-failure territory, not a slow client. Zero
// means "no limit" for every one of these. The deadlines are absolute, so a
// header dripped every second is still cut; ReadHeaderTimeout and ReadTimeout
// each bound the request head (either alone passes the tests; neither, and a
// silent socket is held forever); the TLS handshake runs under the smallest of
// the three read/write timeouts; IdleTimeout bounds keep-alive between
// requests.
func newServer(h http.Handler, errLog *log.Logger) *http.Server {
	s := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 4 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          errLog,
		// "OPTIONS *" reaches route(), which answers it like any preflight.
		DisableGeneralOptionsHandler: true,
		// HTTP/1.1 only, as before the rewrite; h2 would be its own change.
		Protocols: new(http.Protocols),
	}
	s.Protocols.SetHTTP1(true)
	return s
}

type instance struct {
	HTTPAddr, HTTPSAddr, EdgeAddr net.Addr // nil when that listener is off
	servers                       []*http.Server
	errs                          chan error
}

func start(cfg config) (*instance, error) {
	errLog, access := newLogger(cfg.Errors), newLogger(cfg.Access)
	a := &app{access: access, errLog: errLog}
	inst := &instance{errs: make(chan error, 3)}

	serve := func(addr string, limit int, tlsCfg *tls.Config, name string) (net.Addr, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		s := newServer(a, errLog)
		s.TLSConfig = tlsCfg
		inst.servers = append(inst.servers, s)
		limited := netutil.LimitListener(ln, limit)
		go func() {
			var err error
			if tlsCfg != nil {
				err = s.ServeTLS(limited, "", "")
			} else {
				err = s.Serve(limited)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				inst.errs <- fmt.Errorf("%s: %w", name, err)
			}
		}()
		access.Printf("%s listening on %s", name, ln.Addr())
		return ln.Addr(), nil
	}

	var err error
	if inst.HTTPAddr, err = serve(cfg.HTTPAddr, cfg.MaxHTTPConns, nil, "http"); err != nil {
		return nil, err
	}
	// TLS is optional so the service runs locally; certs are read once, so a
	// renewal needs a restart.
	if certs := loadCerts(cfg, errLog); cfg.HTTPSAddr != "" && certs != nil {
		if inst.HTTPSAddr, err = serve(cfg.HTTPSAddr, cfg.MaxTLSConns, tlsConfig(certs), "https"); err != nil {
			inst.shutdown(context.Background())
			return nil, err
		}
	}
	// The cf. front door's own listener: loopback-only, its own cap, so a flood
	// that fills the public :80's slots cannot take the edge view down with it.
	// CF-* trust still rests on the loopback SOURCE, not on which listener.
	if cfg.EdgeAddr != "" {
		if inst.EdgeAddr, err = serve(cfg.EdgeAddr, cfg.MaxEdgeConns, nil, "edge"); err != nil {
			inst.shutdown(context.Background())
			return nil, err
		}
	}
	return inst, nil
}

func (inst *instance) shutdown(ctx context.Context) {
	for _, s := range inst.servers {
		_ = s.Shutdown(ctx)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		port := os.Getenv("HTTP_PORT")
		if port == "" {
			port = "80"
		}
		os.Exit(healthcheck(port))
	}

	cfg := configFromEnv()
	errLog := newLogger(cfg.Errors)
	inst, err := start(cfg)
	if err != nil {
		errLog.Fatalf("startup: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	select {
	case s := <-sig:
		newLogger(cfg.Access).Printf("signal %q received, shutting down", s)
	case err := <-inst.errs:
		errLog.Fatalf("listener failed: %v", err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inst.shutdown(shutdownCtx)
}

var addressLike = regexp.MustCompile(`^[0-9a-fA-F.:]{3,}$`)

// The container HEALTHCHECK (`myip healthcheck`): distroless has no shell, so
// it is this binary or nothing. /ip is the smallest end-to-end path that
// proves the stack works, and the body must look like an address — an error
// page can be a 200.
// ⚠️ Deliberately plain HTTP on loopback: a cert problem is a real incident,
// but not "restart me", and failing health on it would restart-loop the
// container for something a restart cannot fix.
func healthcheck(port string) int {
	c := http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/ip", nil)
	if err != nil {
		return 1
	}
	req.Header.Set("User-Agent", "myip-healthcheck")
	res, err := c.Do(req)
	if err != nil {
		return 1
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 256))
	if err != nil || res.StatusCode != http.StatusOK || !addressLike.MatchString(strings.TrimSpace(string(body))) {
		return 1
	}
	return 0
}
