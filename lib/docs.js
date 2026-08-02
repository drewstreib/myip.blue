// The /docs endpoint: markdown, served as text/plain.
//
// Same content as the HTML page's Usage section — keep the two in sync, they
// are the service's public contract stated twice for two audiences (a browser
// and something parsing text). If you change a route, change both.

export const DOCS_URL = "https://myip.blue/docs";

export const DOCS = `# myip.blue

Connection diagnostics: what your IP, headers and TLS look like from the outside.

## Endpoints

  /          JSON by default; HTML for browsers. See "What / returns".
  /ip        Your IP as a bare string, nothing else. text/plain.
  /json      Full detail: clientIp, timestamp, headers, connection, docs.
  /html      The HTML page, forced, whatever your client asked for.
  /docs      This document. text/plain. Also at /llms.txt.
  /static/*  Static files.

/ip, /json and /html each pin one format; / negotiates between them.
Trailing slashes are accepted on /ip, /json, /html and /docs.

## What / returns

  JSON by default. An Accept: header naming a type wins; failing that, a
  user-agent starting with Mozilla/ gets HTML.

    Accept: application/json  -> JSON
    Accept: text/plain        -> bare IP
    Accept: text/html         -> HTML
    UA starts with Mozilla/   -> HTML
    otherwise                 -> JSON

  Or pin the format by path: /ip, /json, /html.

  Changed 2026-08-02: curl and wget used to get a bare IP from /. If you
  script against this, use /ip -- it is always plain text.

## Hostnames

  myip.blue     http/80 and https/443. Resolves to both ipv4 and ipv6.
  v4.myip.blue  ipv4 only.
  v6.myip.blue  ipv6 only.
  cf.myip.blue  The same service, seen through the Cloudflare edge.

## Fields

  clientIp   Your public IP, as this server sees it.
  timestamp  ISO 8601 UTC, generated per request. If two responses share a
             timestamp, something between you and here is caching.
  headers    Every request header received, verbatim.
  connection How you connected. Differs by hostname:

    myip.blue / v4. / v6.  -- direct to the origin, TLS terminated here, so
      these are your real socket:
        protocol, remotePort, remoteFamily,
        tlsProtocol, cipherName, cipherStandardName

    cf.myip.blue           -- proxied through Cloudflare, so the socket is
      Cloudflare's and the client facts come from its headers:
        via=cloudflare, protocol, remoteFamily,
        country, colo, ray, and tlsVersion/tlsCipher when sent

    Fields Cloudflare did not send are omitted rather than shown empty.

  docs       Link back to this document.

## Notes

  Responses are never cached (no-store).

  CORS is open (Access-Control-Allow-Origin: *), so browser-based tools can
  read this directly. Nothing here is secret: it is all about you.

  myip.blue is deliberately NOT behind a proxy or CDN. It is the control
  measurement: the cleanest path available, so remotePort and the negotiated
  cipher are genuinely yours. cf.myip.blue is the same code behind Cloudflare.
  Request both and diff them to see exactly what the edge changes.

## Examples

  curl myip.blue                             # JSON
  curl myip.blue/ip                          # 1.2.3.4
  curl -H 'Accept: text/plain' myip.blue     # 1.2.3.4
  curl myip.blue/html                        # the page, forced
  curl cf.myip.blue/json                     # the edge's view
`;

// Permissive: this is a public diagnostic service with nothing to hide and
// nothing expensive to crawl. The comment is the only way to point a crawler at
// the machine-readable docs — robots.txt has no standard directive for it.
export const ROBOTS = `User-agent: *
Allow: /

# Machine-readable docs: https://myip.blue/llms.txt
`;
