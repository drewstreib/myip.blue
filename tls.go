package main

import (
	"crypto/tls"
	"log"
)

// 🛑 AS LOW AS GO GOES, ON PURPOSE (Drew, 2026-11-06: "one of the points of
// myip.blue is to be able to show old clients what they're doing"). TLS 1.0 is
// the floor crypto/tls implements, and every suite it still has is enabled —
// InsecureCipherSuites() included. A client that can only speak below this
// (SSLv3, DHE, export, NULL) gets a handshake failure, not a page: Go has none
// of those. TLS 1.3 suites are not configurable; all three are always on.
func tlsConfig(certs []tls.Certificate) *tls.Config {
	var suites []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		suites = append(suites, s.ID)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS10,
		CipherSuites: suites,
		Certificates: certs,
	}
}

// loadCerts returns the primary pair plus the optional RSA pair, or nil when
// the primary cannot be read: TLS is optional so the service runs locally.
func loadCerts(cfg config, errLog *log.Logger) []tls.Certificate {
	primary, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		errLog.Printf("TLS disabled: %v. HTTP only on %s.", err, cfg.HTTPAddr)
		return nil
	}
	certs := []tls.Certificate{primary}
	if cfg.TLSRSACert != "" {
		rsa, err := tls.LoadX509KeyPair(cfg.TLSRSACert, cfg.TLSRSAKey)
		if err != nil {
			errLog.Printf("RSA certificate not loaded, RSA-only clients will fail: %v", err)
		} else {
			certs = append(certs, rsa)
		}
	}
	return certs
}

// The names the Node version reported (OpenSSL's getProtocol()), kept so the
// `tlsProtocol` field did not change with the rewrite.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return tls.VersionName(v)
}

// `cipherName` is OpenSSL's name for the suite, as the Node version reported
// it; Go knows only the IANA name (`cipherStandardName`). One row per suite
// crypto/tls implements, checked against `openssl ciphers -stdname` by
// TestOpenSSLNamesMatchOpenSSL. A suite with no row reports its IANA name.
var openSSLNames = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                      "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "DES-CBC3-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:                  "AES128-SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:                  "AES256-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               "AES128-SHA256",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               "AES128-GCM-SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               "AES256-GCM-SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "ECDHE-ECDSA-RC4-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "ECDHE-ECDSA-AES128-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "ECDHE-ECDSA-AES256-SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "ECDHE-RSA-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "ECDHE-RSA-DES-CBC3-SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "ECDHE-RSA-AES128-SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "ECDHE-RSA-AES256-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "ECDHE-ECDSA-AES128-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "ECDHE-RSA-AES128-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "ECDHE-RSA-AES128-GCM-SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "ECDHE-ECDSA-AES128-GCM-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "ECDHE-RSA-AES256-GCM-SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "ECDHE-ECDSA-AES256-GCM-SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "ECDHE-RSA-CHACHA20-POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "ECDHE-ECDSA-CHACHA20-POLY1305",
	// OpenSSL names the TLS 1.3 suites by their IANA names.
	tls.TLS_AES_128_GCM_SHA256:       "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:       "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256",
}

func openSSLName(id uint16) string {
	if n, ok := openSSLNames[id]; ok {
		return n
	}
	return tls.CipherSuiteName(id)
}
