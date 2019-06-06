module.exports = {
    express: {
        port: 3000,
    },
    sso: {
        // Encode your public key in base64 below. You can retrieve it from the server by going to https://{your_sso_proxy_server}/oauth2/v1/certs
        publicKey: 'base64encodedKey'
    }
};
