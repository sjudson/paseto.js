const sodium = require('libsodium-wrappers');

const utils               = require('../utils');
const InvalidVersionError = require('../error/InvalidVersionError');


/***
 * V2
 *
 * protocol version 2
 *
 * @constructor
 * @api public
 */
module.exports = V2;
function V2() { this._header = 'v2'; }


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
V2.prototype.header = header;
function header () {
  return this._header;
}


/***
 * encrypt
 *
 * symmetric authenticated encryption
 *
 * @function
 * @api public
 *
 * @param data {String|Buffer}
 * @param key {Object}
 * @param footer {String|Buffer}
 * --- we do not document provided nonce, for testing ---
 * @param cb {Function}
 * @returns token {String}
 */
V2.prototype.encrypt = encrypt;
function encrypt(data, key, footer, nonce, cb) {
  if (typeof nonce === 'function') {
    cb    = nonce;
    nonce = undefined;
  }

  const self = this;
  const done = utils.ret(cb);

  [ data, footer, nonce ] = utils.parse(data, footer, nonce);

  const header = self.header();
  const prefix = header + '.local.';

  let token;
  try {
    token = aeadEncrypt(key, prefix, data, footer, nonce);
  } catch (ex) {
    return done(ex);
  }

  return done(null, token);
}


/***
 * decrypt
 *
 * symmetric authenticated decryption
 *
 * @function
 * @api public
 *
 * @param token {String}
 * @param key {Object}
 * @param footer {String|Buffer}
 * @param cb {Function}
 * @returns data {String}
 */
V2.prototype.decrypt = decrypt
function decrypt(token, key, footer, cb) {
  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  const header = self.header;
  const prefix = header + '.local.';

  try {
    data = aeadDecrypt(key, prefix, token, footer);
  } catch (ex) {
    return done(ex);
  }

  return done(null, data);
}


/***
 * aeadEncrypt
 *
 * internals of symmetric authenticated encryption
 *
 * @function
 * @api private
 *
 * @param key {Object}
 * @param prefix {Buffer}
 * @param plaintext {Buffer}
 * @param footer {Buffer}
 * --- we do not document provided nonce, for testing ---
 * @returns token {String}
 */
V2.prototype.aeadEncrypt = aeadEncrypt;
function aeadEncrypt(key, prefix, plaintext, footer, nonce) {

  // build nonce

  const nlen   = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const nkey   = nonce || sodium.randombytes_buf(nlen);
  const _nonce = sodium.crypto_generichash(nlen, plaintext, nkey);

  nonce = Buffer.from(_nonce);

  // encrypt

  const ad          = utils.pae(prefix, nonce, footer);
  const _ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key.raw());

  const ciphertext  = Buffer.from(_ciphertext);

  // format

  const payload = Buffer.concat([ nonce, ciphertext ]);
  const token   = prefix + utils.toB64URLSafe(payload);

  return (!footer.byteLength)
    ? token
    : token + '.' + utils.toB64URLSafe(footer);
}
