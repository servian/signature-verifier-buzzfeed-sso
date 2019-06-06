# SSO Signature Verifier for Buzzfeed SSO

[Buzzfeed SSO](https://github.com/buzzfeed/sso) is a simple easy-to-use Single Sign-On Proxy that can help protect web applications via a secured reverse proxy.

The `sso_proxy` component of Buzzfeed SSO allows signing of every request, so that you can determine whether the request entering your service has legitimately come from the `sso_proxy`.

This is a simple drop-in library which you can add to your NodeJS applications to verify the signature of the calling application.

## Prerequisites

### Certificate setup

Your `sso_proxy` needs to be configured to sign requests.

You can generate a certificate by running `openssl genrsa 2048 | openssl pkcs8 -topk8 -inform pem -outform pem -nocrypt` and copying the relevant output into a `.pem` file.

The `sso_proxy` application needs this certificate defined in an environment variable. An example shell script is below:

```
#!/bin/bash
export EMAIL_DOMAIN=yourdomain.com
export VIRTUAL_HOST=*.sso.yourdomain.com
# ... other config variables here...
export REQUEST_SIGNATURE_KEY=$(cat /path/to/cert.pem)

/path/to/sso-proxy
```

Once the proxy is up and running, you can grab the public key needed for this library by going to `{sso_proxy_host}/oauth2/v1/certs`.
You'll want the part of the certificate that starts with `-----BEGIN RSA PUBLIC KEY----- `. Be sure to copy the whole thing and make sure you don't miss the newline character at the end!

## Installation

`npm install signature-verifier-buzzfeed-sso`

Then in your code:

```
const SSOVerifier = require('signature-verifier-buzzfeed-sso');
const sso = new SSOVerifier(publicKeyString);   // Your Public key including the training newline

// Later on when you have headers, url and body
const isSignatureValid = sso.verifySignature(url, headers, body);
if (!isSignatureValid) {
    // Do whatever you need to
}
```

## Examples

There are some examples in the `examples` directory which might help you get started.

### Express

Check out this repository, then:

* `cd examples/express`
* `npm install`
* Edit the `config.js` file and replace the `base64encodedKey` with a base64 encoded version of your public key
* Run with `npm run start`
* Configure an upstream server on your SSO proxy
* Try accessing directly (ie not through the proxy) - see the failure
* Try accessing through the proxy - see the success!
