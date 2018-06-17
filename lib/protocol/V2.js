const sodium = require('libsodium-wrappers');

const utils       = require('../utils')
const decapsulate = require('../decapsulate');

const PasetoError         = require('../error/PasetoError');
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
  this._repr = 'v2';

  this._constants = {
    SYMMETRIC_KEY_BYTES: 32
  }
}


/***
 * generateAsymmetricSecretKey
 *
 * generate an asymmetric secret key for use with the protocol
 *
 * @function
 * @api public
 *
 * @returns {AsymmetricSecretKey}
 */
V2.generateAsymmetricSecretKey = generateAsymmetricSecretKey;
function generateAsymmetricSecretKey() {
  // minor hack to mimic php api without circular dependency - probably a better way to do this
  return require('../key/secret').generate(new V2());
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
  return require('../key/symmetric').generate(new V2());
}


/***
 * repr
 *
 * get protocol representation
 *
 * @function
 * @api public
 *
 * @returns {String}
 */
V2.prototype.repr = repr;
function repr() {
  return this._repr;
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

  const header = utils.local(self);

  [ data, footer, nonce ] = (utils.parse('utf-8'))(data, footer, nonce);

  let token;
  try {
    token = aeadEncrypt(key, header, data, footer, nonce);
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

  let local, header = utils.local(self);
  try {
    [ header, payload, footer ] = decapsulate(header, token, footer); 
  } catch (ex) {
    return done(ex);
  }

  try {
    data = aeadDecrypt(key, header, payload, footer);
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

  const header = utils.public(self);

  [ data, footer ] = (utils.parse('utf-8'))(data, footer);

  // sign

  const payload    = utils.pae(header, data, footer);
  const _signature = sodium.crypto_sign_detached(payload, key.raw());
  const signature  = Buffer.from(_signature);

  // format

  const token = header.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([ data, signature ]));

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

  let payload, header = utils.public(self);
  try {
    [ header, payload, footer ] = decapsulate(header, token, footer); 
  } catch (ex) {
    return done(ex);
  }

  const plen = Buffer.byteLength(payload);

  // recover data

  const data      = Buffer.from(payload).slice(0, plen - sodium.crypto_sign_BYTES);
  const signature = Buffer.from(payload).slice(plen - sodium.crypto_sign_BYTES);

  // verify signature

  const expected = utils.pae(header, data, footer);
  const valid    = sodium.crypto_sign_verify_detached(signature, expected, key.raw());

  if (!valid) { return done(new PasetoError('Invalid signature for this message')); }

  // format

  return done(null, data.toString('utf-8'));
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
 * @param {Buffer} header
 * @param {Buffer} plaintext
 * @param {Buffer} footer
 * @param {Buffer} nonce
 * @returns {String} token
 */
V2.prototype.aeadEncrypt = aeadEncrypt;
function aeadEncrypt(key, header, plaintext, footer, nonce) {

  // build nonce

  const nlen   = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const nkey   = nonce || sodium.randombytes_buf(nlen);
  const _nonce = sodium.crypto_generichash(nlen, plaintext, nkey);

  nonce = Buffer.from(_nonce);

  // encrypt

  const ad          = utils.pae(header, nonce, footer);
  const _ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key.raw());
  const ciphertext  = Buffer.from(_ciphertext);

  // format

  const payload = Buffer.concat([ nonce, ciphertext ]);
  const token   = header.toString('utf-8') + utils.toB64URLSafe(payload);

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
 * @param {Buffer} header
 * @param {Buffer} payload
 * @param {Buffer} footer
 * @returns {String} plaintext
 */
V2.prototype.aeadDecrypt = aeadDecrypt;
function aeadDecrypt(key, header, payload, footer) {

  const plen = Buffer.byteLength(payload);

  // recover nonce

  const nlen  = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const nonce = Buffer.from(payload).slice(0, nlen);

  // decrypt and verify

  const ad         = utils.pae(header, nonce, footer);
  const ciphertext = Buffer.from(payload).slice(nlen, plen);

  const _plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key.raw());
  const plaintext  = Buffer.from(_plaintext);

  // format

  return plaintext.toString('utf-8');
}
