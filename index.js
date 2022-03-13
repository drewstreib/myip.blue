const express = require('express');
const nocache = require('nocache');
const requestIp = require('request-ip');

const app = express();
const port = 8080;

app.use(nocache());
app.use('/static', express.static('static'))
app.set('views', './views');
app.set('view engine', 'pug');

// since we're going through proxy, this host header is meaningless
app.use(function (req, res, next) {
    delete req.headers['host'];
    var myip = requestIp.getClientIp(req);
    if (myip.substr(0, 7) == "::ffff:") { myip = myip.substr(7); }
    req.myip = myip;
    next();
});

app.get('/', (req, res) => {
    out = {
        "clientIp": req.myip,
        "headers": req.headers
    }

    // send plain response for some agents
    do_plain = [ 'curl', 'wget' ]; 
    if (do_plain.includes(req.header('User-Agent').substr(0, 4))) {
        res.set({ 'Content-Type': 'text/plain', });
        res.send(req.myip);       
    } else {
        res.render('index', out);
    }
});

app.get('/ip/', (req, res) => {
    res.set({ 'Content-Type': 'text/plain', });
    res.send(req.myip);       
});

app.get('/json/', (req, res) => {
    out = {
        "clientIp": req.myip,
        "headers": req.headers
    }
    res.header("Content-Type",'application/json');
    res.json(out);
});

app.use((req, res, next) => {
  res.status(404).send("Sorry! Blue can't find that!")
})

app.listen(port, () => console.log(`***** app listening on port ${port}!`));

