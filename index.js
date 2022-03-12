const bodyParser = require('body-parser');
const express = require('express');
const nocache = require('nocache');
const requestIp = require('request-ip');

const app = express();
const port = 8080;

app.use(bodyParser.json());
app.use(nocache());

app.get('/', (req, res) => {
    var clientIp = requestIp.getClientIp(req);
    console.log(clientIp);
    res.send(clientIp);
});

app.listen(port, () => console.log(`Hello world app listening on port ${port}!`));

