// Container HEALTHCHECK. Runs inside the image (distroless has no shell, so
// this cannot be a curl one-liner — it is node or nothing).
//
// Checks /ip because it is the smallest end-to-end path that still proves the
// whole stack works: the listener accepted, routing ran, the client address was
// resolved, and a well-formed body came back. A TCP-connect check would pass on
// a process that had stopped serving.
//
// ⚠️ Deliberately hits HTTP on loopback, not HTTPS: this tests the app, not the
// certificate. A cert problem is a real incident but it is not "restart me",
// and failing health on it would restart-loop the container for something a
// restart cannot fix.

const port = process.env.HTTP_PORT ?? 80;
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), 2000);

try {
  const res = await fetch(`http://127.0.0.1:${port}/ip`, {
    signal: controller.signal,
    headers: { "user-agent": "myip-healthcheck" },
  });
  if (!res.ok) process.exit(1);
  const body = (await res.text()).trim();
  // Must look like an address, not just be non-empty — an error page is 200-able.
  process.exit(/^[0-9a-fA-F.:]{3,}$/.test(body) ? 0 : 1);
} catch {
  process.exit(1);
} finally {
  clearTimeout(timer);
}
