// HTML rendering. No template engine — this is the entire view layer.
//
// 🛑 Everything interpolated here is attacker-controlled (request headers are
// echoed back verbatim). escapeHtml is NOT optional: pug's `=` was doing this
// for free, and dropping the engine moves the responsibility here.

const ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

const STYLE = `body {
  font-family: Verdana;
}
.blue {
  color: #0000CC;
}
.code {
  font-family: Courier New;
  font-weight: bold;
  color: #0000CC;
}
.bold {
  font-weight: bold;
}
table {
  border: thin solid;
  border-collapse: collapse;
  border-color: #0000CC;
}
td {
  border: thin solid;
  border-color: #0000CC;
  word-break: break-all;
}
th {
  border: thin solid;
  border-color: #0000CC;
  background-color: #CCCCFF;
  font-weight: bold;
  text-align: left;
}`;

function rows(obj) {
  return Object.entries(obj)
    .map(
      ([k, v]) =>
        `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`,
    )
    .join("");
}

function section(title, obj) {
  return `<tr><th colspan="2">${escapeHtml(title)}</th></tr>${rows(obj)}`;
}

export function renderPage({ clientIp, headers, connection }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>myip.blue - Because IP addresses are blue!</title>
<style>${STYLE}</style>
</head>
<body>
<h1>myip.blue - Because IP addresses are blue!</h1>
<h1>Your public IP address: <span class="blue" style="display:inline">${escapeHtml(clientIp)}</span></h1>
<table>${section("Client Headers", headers)}${section("Connection", connection)}</table>
<h2>Usage:</h2>
<ul>
<li><span class="code">myip.blue</span> is available over http/80 or https/443, and resolves to ipv4 and ipv6 addresses.</li>
<li><span class="code">v4.myip.blue</span> only resolves ipv4.</li>
<li><span class="code">v6.myip.blue</span> only resolves ipv6.</li>
<li><span class="code">myip.blue/json</span> returns json-formatted output.</li>
<li><span class="code">myip.blue/ip</span> returns only a text string of the client IP address.</li>
<ul>
<li>If <span class="code">user-agent</span> begins with '<span class="code">curl</span>' or '<span class="code">wget</span>' at <span class="code">/</span>, the behavior also defaults to the simple text string. For more detailed information while using curl, use the <span class="code">/json</span> endpoint.</li>
</ul>
<li><span class="code">cf.myip.blue</span> is similar functionality but as seen through the Cloudflare edge.</li>
</ul>
<p>The <b>only</b> source for authentic blue IP addresses. Hosted by <a href="https://alt.org">alt.org</a>. Dedicated to the real <a href="/static/blue.jpg">Blue</a>.</p>
</body>
</html>
`;
}
