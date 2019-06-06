const config = require('./config');
const express = require('express');
const bodyParser = require('body-parser');
const SSOVerifier = require('../../src/index');
const app = express();

const sso = new SSOVerifier(Buffer.from(config.sso.publicKey, 'base64'));

app.use(bodyParser.raw({
    inflate: true,
    limit: '1MB',
    type: '*/*'
}));

// Example middleware for a typical JSON API that validates the signature
app.use((req, res, next) => {
    // Unfortunately we need the RAW body - we can convert to JSON later
    req.rawBody = (req.body && Buffer.isBuffer(req.body)) ? req.body : '';
    if (sso.verifySignature(req.url, req.headers, req.rawBody.toString('utf8')) !== true) {
        res.statusCode = 500;
        res.type('json');
        return res.send({
            error: 'Invalid Signing Token',
            method: req.method,
            signatureOK: false,
            headers: req.headers,
            body: req.rawBody,
        });
    }
    if (req.headers['content-type'] && req.headers['content-type'].toLocaleLowerCase() === 'application/json') {
        try {
            req.body = JSON.parse(req.rawBody.toString('utf8'));
        } catch (err) {
            res.statusCode = 500;
            res.type('json');
            return res.send({ error: 'You supplied invalid JSON' });
        }
    }
    return next();
});

app.all('*', (req, res) => {
    return res.send({
        signatureOK: true,
        url: req.protocol + '://' + req.get('host') + req.originalUrl,
        method: req.method,
        headers: req.headers,
        body: (Buffer.isBuffer(req.body)) ? req.body.toString('utf8') : req.body,
    });
});



app.listen(config.express.port, () => console.log(`Example SSO Signature Verifier is listening on port ${config.express.port}!`));
