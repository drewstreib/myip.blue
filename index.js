//const bodyParser = require('body-parser');
const express = require('express');
const nocache = require('nocache');
const requestIp = require('request-ip');

const app = express();
const port = 8080;

//app.use(bodyParser.json());
app.use(nocache());
app.use('/static', express.static('static'))
app.set('views', './views');
app.set('view engine', 'pug');

function deforward(headers) {
    var nh = { ...headers };
    delete nh['host'];
    return nh;
}

app.get('/', (req, res) => {
    var clientIp = requestIp.getClientIp(req);
    if (clientIp.substr(0, 7) == "::ffff:") { clientIp = clientIp.substr(7) }

    out = {
        "clientIp": clientIp,
        "headers": deforward(req.headers)
    }

    // send plain response for some agents
    do_plain = [ 'curl', 'wget' ]; 
    if (do_plain.includes(req.header('User-Agent').substr(0, 4))) {
        res.set({ 'Content-Type': 'text/plain', });
        res.send(clientIp);       
    } else {
        res.render('index', out);
    }
});

app.get('/json/', (req, res) => {
    var clientIp = requestIp.getClientIp(req);
    if (clientIp.substr(0, 7) == "::ffff:") { clientIp = clientIp.substr(7) } 

    out = {
        "clientIp": clientIp,
        "headers": deforward(req.headers)
    }
    res.header("Content-Type",'application/json');
    res.json(out);
});

app.listen(port, () => console.log(`***** app listening on port ${port}!`));

