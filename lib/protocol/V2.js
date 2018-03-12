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
 * @param {String|Buffer} data
 * @param {Object} key
 * @param {String|Buffer} footer
 * --- we do not document provided nonce, for testing ---
 * @param {Function} cb
 * @returns {String} token
 */
V2.prototype.encrypt = encrypt;
function encrypt(data, key, footer, nonce, cb) {
  if (typeof nonce === 'function') {
    cb    = nonce;
    nonce = undefined;
  }
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  const header = self.header();
  let prefix = header + '.local.';

  [ prefix, data, footer, nonce ] = utils.parse(prefix, data, footer, nonce);

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
 * @param {String} token
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {Function} cb
 * @returns {String} data
 */
V2.prototype.decrypt = decrypt
function decrypt(token, key, footer, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  const header = self.header();
  let prefix = header + '.local.';

  // parses as utf-8, we'll handle as base64url manually
  [ prefix, token, footer ] = utils.parse(prefix, token, footer);

  try {
    data = aeadDecrypt(key, prefix, utils.varfooter(token, footer), footer);
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
 * @param {Object} key
 * @param {Buffer} prefix
 * @param {Buffer} plaintext
 * @param {Buffer} footer
 * --- we do not document provided nonce, for testing ---
 * @returns {String} token
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
  const token   = prefix.toString('ascii') + utils.toB64URLSafe(payload);

  return (!Buffer.byteLength(footer))
    ? token
    : token + '.' + utils.toB64URLSafe(footer);
}


/***
 * aeadDecrypt
 *
 * internals of symmetric authenticated decryption
 *
 * @function
 * @api private
 *
 * @param {Object} key
 * @param {Buffer} payload
 * @returns {String} plaintext
 */
V2.prototype.aeadDecrypt = aeadDecrypt;
function aeadDecrypt(key, prefix, token, footer) {

  // compare header

  const elen  = Buffer.byteLength(prefix);
  const given = Buffer.from(token).slice(0, elen);

  if (prefix.compare(given) !== 0) { throw new Error('Invalid message header.'); }

  // decode payload, we have to reencode as utf-8 first

  const reencoded = Buffer.from(token).slice(elen).toString('utf-8');
  const decoded   = utils.fromB64URLSafe(reencoded);
  const mlen      = Buffer.byteLength(decoded);

  // recover nonce

  const nlen  = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const nonce = Buffer.from(decoded).slice(0, nlen);

  // decrypt and verify

  const ad         = utils.pae(prefix, nonce, footer);
  const ciphertext = Buffer.from(decoded).slice(nlen, mlen);

  const _plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key.raw());
  const plaintext  = Buffer.from(_plaintext);

  // format

  return plaintext.toString('utf-8');
}
