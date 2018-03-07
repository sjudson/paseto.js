const sodium = require('libsodium-wrappers');

const utils = require('../utils');


/***
 * V2
 *
 * protocol version 2
 *
 * @constructor
 * @api public
 */
module.exports = V2;
function V2() {
  self.header = 'v2';
}


/***
 * header
 *
 * get protocol header
 *
 * @function
 * @api public
 *
 * @returns {String}
 */
V2.prototype.header = () => { return this.header; }


/***
 * encrypt
 *
 * symmetric authenticated encryption
 *
 * @function
 * @api public
 *
 * @param data {Buffer}
 * @param key {Buffer}
 * @param footer {String}
 * @param cb {Function}
 * @returns token {String}
 */
V2.prototype.encrypt = (data, key, footer, cb) => {
  const self = this;
  const done = utils.ret(cb);

  const header = self.header;
  const prefix = header + '.local.';

  let token;
  try {
    token = aeadEncrypt(key, prefix, data, footer);
  } catch (ex) {
    return done(ex);
  }

  return done(null, token);
}


/***
 * aeadEncrypt
 *
 * internals of symmetric authenticated encryption
 *
 * @function
 * @api private
 *
 * @param key {Buffer}
 * @param prefix {Buffer}
 * @param plaintext {Buffer}
 * @param footer {String}
 * @returns token {String}
 */
V2.prototype.aeadEncrypt = (key, prefix, plaintext, footer) => {
  footer = footer || '';

  // build nonce

  const nlen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

  const nkey  = sodium.randombytes_buf(nlen);
  const nonce = sodium.crypto_generichash(nlen, plaintext, nkey);

  // encrypt

  const ad         = utils.encodead(prefix, plaintext, footer);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key);

  // format

  const payload = Buffer.concat([ nonce, ciphertext ]);
  const token   = prefix + utils.toB64URLSafe(payload);

  return (!footer)
    ? token
    : token + '.' + utils.toB64URLSafe(footer);
}
