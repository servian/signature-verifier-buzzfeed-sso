const crypto = require('crypto');
const URLLib = require('url');

/**
 * A class to help verify authenticity of requests from Buzfeed SSO proxy
 * See {@link https://github.com/buzzfeed/sso}
 */
class SSOVerify {

  /**
   * Create a new SSOVerify instance
   * @param {string} publicKeyString Public Key
   */
  constructor(publicKeyString) {
    this.publicKeyString = publicKeyString;
  }

  /**
   * Verifies the request
   * @param {string} url The full request URL
   * @param {object} headers HTTP Headers as key->value pair
   * @param {string} rawBody The raw HTTP body as a string
   * @return {boolean} TRUE if valid signature
   */
  verifySignature(url, headers, rawBody = '') {
    if (!headers['sso-signature'] || !headers.kid) {
      return false; // Missing Signature or Key ID
    }
    const signatureHeader = Buffer.from(headers['sso-signature'], 'base64');
    const hashToVerify = crypto.publicDecrypt({
      key: this.publicKeyString,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    }, signatureHeader);
    const requestPayload = this.getRequestPayload(url, headers, rawBody);
    const ourHash = crypto.createHash('sha256').update(requestPayload).digest('hex');

        // Verify Key ID
    if (!this.keyIdValid(headers.kid)) {
      return false;
    }
    const hashMatch = `3031300d060960864801650304020105000420${ourHash}` === hashToVerify.toString('hex'); // RFC3447
    if (!hashMatch) {
        // Sometimes the server puts in content length in the upstream request, but it doesn't have it on the original request
        const contentLengthIdx = Object.keys(headers).map(a => a.toLocaleLowerCase()).indexOf('content-length');
        if (contentLengthIdx !== -1) {
            // Remove content length and try again
            const newHeaders = JSON.parse(JSON.stringify(headers));
            Object.keys(newHeaders).forEach(nh => {
                if (nh.toLocaleLowerCase() === 'content-length') {
                    delete newHeaders[nh];
                }
            });
            return this.verifySignature(url, newHeaders, rawBody);
        }
    }
    return hashMatch
  }

  /**
   * Verify if the Key ID is valid
   * @param {string} kid Key ID
   * @return {boolean} TRUE if key id is valid
   */
  keyIdValid(kid) {
    const hash = crypto.createHash('sha256');
    hash.update(this.publicKeyString);
    const kidToVerify = hash.digest('hex');
    return kidToVerify === kid;
  }

  /**
   * Gets the request payload suitable for hashing
   * @param {string} url The full request URL
   * @param {object} headers HTTP Headers
   * @param {string} rawBody The raw HTTP body as a string
   * @return {string} The output ready to be hashed
   */
  getRequestPayload(url, headers, rawBody) {
    const signedHeaders = [
      'Content-Length',
      'Content-Md5',
      'Content-Type',
      'Date',
      'Authorization',
      'X-Forwarded-User',
      'X-Forwarded-Email',
      'X-Forwarded-Groups',
      'X-Forwarded-Access-Token',
      'Cookie',
    ];
    const output = [];
    const requestHeaders = Object.keys(headers).map(h => ({
      header: h.toLocaleLowerCase(),
      value: headers[h],
    }));

    // First the headers
    signedHeaders.forEach((sh) => {
      const matchingHeaders = requestHeaders
        .filter(a => a.header === sh.toLocaleLowerCase() && a.value.length > 0);
      if (matchingHeaders.length > 0) {
        output.push(matchingHeaders.map(a => a.value).join(','));
      }
    });

    // Now the URL
    const requestUrl = URLLib.parse(url);
    let canonicalUrl = requestUrl.path;
    if (requestUrl.hash && requestUrl.hash.length > 0) {
      canonicalUrl += requestUrl.hash;
    }
    output.push(canonicalUrl);

    // Now the string body
    if (rawBody) {
      output.push(rawBody);
    } else {
      output.push('');
    }

    const outputToHash = output.join('\n');
    return outputToHash;
  }
}

module.exports = SSOVerify;
