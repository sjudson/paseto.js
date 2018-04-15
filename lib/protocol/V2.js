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
function V2() {
  this._header = 'v2';

  this._constants = {
    SYMMETRIC_KEY_BYTES: 32
  }
}


/***
 * generateSymmetricKey
 *
 * generate a symmetric key for use with the protocol
 *
 * @function
 * @api public
 *
 * @returns {SymmetricKey}
 */
V2.generateSymmetricKey = generateSymmetricKey;
function generateSymmetricKey() {
  // minor hack to mimic php api without circular dependency - probably a better way to do this
  // return require('../key/symmetric').generate(new V2());
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
V2.prototype.header = header;
function header() {
  return this._header;
}


/***
 * getSymmetricKeyByteLength
 *
 * get symmetric length
 *
 * @function
 * @api public
 *
 * @returns {Number}
 */
V2.prototype.getSymmetricKeyByteLength = getSymmetricKeyByteLength;
function getSymmetricKeyByteLength() {
  return this._constants.SYMMETRIC_KEY_BYTES;
}


/***
 * __encrypt
 *
 * symmetric authenticated encryption
 *
 * @function
 * @api private
 *
 * @param {String|Buffer} data
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {String|Buffer} nonce
 * @param {Function} cb
 * @returns {String} token
 */
V2.prototype.__encrypt = __encrypt;
function __encrypt(data, key, footer, nonce, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

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
 * encrypt
 *
 * symmetric authenticated encryption (public api)
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} data
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {Function} cb
 * @returns {String} token
 */
V2.prototype.encrypt = encrypt;
function encrypt(data, key, footer, cb) {
  return this.__encrypt(data, key, footer, '', cb);
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
 * sign
 *
 * asymmetric authentication
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} data
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {Function} cb
 * @returns {String} token
 */
V2.prototype.sign = sign;
function sign(data, key, footer, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  const header = self.header();
  let prefix = header + '.public.';

  [ prefix, data, footer ] = utils.parse(prefix, data, footer);

  // sign

  const payload    = utils.pae(prefix, data, footer);
  const _signature = sodium.crypto_sign_detached(payload, key.raw());
  const signature  = Buffer.from(_signature);

  // format

  const token = prefix.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([ payload, signature ]));

  return (!Buffer.byteLength(footer))
    ? done(null, token)
    : done(null, token + '.' + utils.toB64URLSafe(footer));
}


/***
 * verify
 *
 * asymmetric authentication
 *
 * @function
 * @api public
 *
 * @param {String} token
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {Function} cb
 * @returns {String} token
 */
V2.prototype.verify = verify;
function verify(token, key, footer, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  const header = self.header();
  let prefix = header + '.public.';

  // parses as utf-8, we'll handle as base64url manually
  [ prefix, token, footer ] = utils.parse(prefix, token, footer);

  token = utils.varfooter(token, footer);

  // compare header

  const elen  = Buffer.byteLength(prefix);
  const given = Buffer.from(token).slice(0, elen);

  if (!utils.cnstcomp(prefix, given)) { return done(new Error('Invalid message header.')); }

  // decode payload, we have to reencode as utf-8 first

  const reencoded = Buffer.from(token).slice(elen).toString('utf-8');

  let decoded;
  try {
    decoded = utils.fromB64URLSafe(reencoded);
  } catch (ex) {
    return done(new PasetoError('Invalid encoding detected'));
  }

  const mlen = Buffer.byteLength(decoded);

  // recover data

  const data      = Buffer.from(decoded).slice(0, mlen - sodium.crypto_sign_BYTES);
  const signature = Buffer.from(decoded).slice(mlen - sodium.crypto_sign_BYTES);

  // verify signature

  const expected = utils.pae(prefix, data, footer);
  const valid    = sodium.crypto_sign_verify_detached(signature, expected, key.raw());

  if (!valid) { return done(new PasetoError('Invalid signature for this message')); }

  // format

  return data.toString('utf-8');
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
 * @param {Buffer} nonce
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
  const token   = prefix.toString('utf-8') + utils.toB64URLSafe(payload);

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
 * @param {Buffer} prefix
 * @param {Buffer} token
 * @param {Buffer} footer
 * @returns {String} plaintext
 */
V2.prototype.aeadDecrypt = aeadDecrypt;
function aeadDecrypt(key, prefix, token, footer) {

  // compare header

  const elen  = Buffer.byteLength(prefix);
  const given = Buffer.from(token).slice(0, elen);

  if (!utils.cnstcomp(prefix, given)) { throw new Error('Invalid message header.'); }

  // decode payload, we have to reencode as utf-8 first

  const reencoded = Buffer.from(token).slice(elen).toString('utf-8');

  let decoded;
  try {
    decoded = utils.fromB64URLSafe(reencoded);
  } catch (ex) {
    throw new PasetoError('Invalid encoding detected');
  }

  const mlen = Buffer.byteLength(decoded);

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
