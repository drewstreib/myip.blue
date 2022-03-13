const express = require("express");
const fs = require("fs");
const https = require("https");
const nocache = require("nocache");

const port = 8080;
const port_https = 8081;

const https_options = {
  key: fs.readFileSync("/key.pem"),
  cert: fs.readFileSync("/chain.pem"),
};

const app = express();
app.use(nocache());
app.use("/static", express.static("static"));
app.set("views", "./views");
app.set("view engine", "pug");

app.use(function (req, res, next) {
  // get conn info
  if (req.protocol === "https") {
    req.myconn = {
      protocol: "https",
      remotePort: req.socket.remotePort,
      tlsProtocol: req.socket.getProtocol(),
      cipherName: req.socket.getCipher()["name"],
      cipherStandardName: req.socket.getCipher()["standardName"],
      cipherMinVersion: req.socket.getCipher()["version"],
    };
    // req.mysharedalgs = req.socket.getSharedSigalgs();
  } else {
    req.myconn = {
      protocol: "http",
      remotePort: req.socket.remotePort,
    };
    // req.mysharedalgs = [];
  }

  // ipv4 addresses are in ipv6 notation. this fixes it.
  var myip = req.ip;
  if (myip.substr(0, 7) == "::ffff:") {
    myip = myip.substr(7);
    req.myconn["remoteFamily"] = "IPv4";
  } else {
    req.myconn["remoteFamily"] = "IPv6";
  }
  req.myip = myip;
  next();
});

app.get("/", (req, res) => {
  out = {
    clientIp: req.myip,
    headers: req.headers,
    connection: req.myconn
    // sharedalgs: req.mysharedalgs,
  };

  // send plain response for some agents
  do_plain = ["curl", "wget"];
  if (do_plain.includes(req.header("User-Agent").substr(0, 4))) {
    res.set({ "Content-Type": "text/plain" });
    res.send(req.myip);
  } else {
    res.render("index", out);
  }
});

app.get("/ip/", (req, res) => {
  res.set({ "Content-Type": "text/plain" });
  res.send(req.myip);
});

app.get("/json/", (req, res) => {
  out = {
    clientIp: req.myip,
    headers: req.headers,
    connection: req.myconn,
  };
  /* if (req.myconn.protocol == "https") {
    out.connection["sharedSigalgs"] = req.mysharedalgs;
  } */
  res.header("Content-Type", "application/json");
  res.json(out);
});

app.use((req, res, next) => {
  res.status(404).send("Sorry! Blue can't find that!");
});

app.listen(port, () =>
  console.log(
    `***** app listening on port ${port}! TLS will launch on ${port_https}!`
  )
);
https.createServer(https_options, app).listen(port_https);
