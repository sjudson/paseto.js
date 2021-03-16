const sodium = require('libsodium-wrappers-sumo');

const V2          = require('./common');
const utils       = require('../../utils/node');
const decapsulate = require('../../decapsulate');

const PasetoError         = require('../../error/PasetoError');
const InvalidVersionError = require('../../error/InvalidVersionError');


/***
 * _nodeV2
 *
 * protocol version 2
 *
 * @constructor
 * @api public
 */
module.exports = _nodeV2;
function _nodeV2() {
  V2.call(this);

  this._constants[ 'SYMMETRIC_KEY_BYTES' ] = 32;
}
_nodeV2.super_ = V2;
_nodeV2.prototype = Object.create(V2.prototype, {
  constructor: { value: _nodeV2, enumerable: false, writeable: true }
});


/***
 * private
 *
 * generate a private key for use with the protocol
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
_nodeV2.prototype.private = pk;
function pk(cb) {
  const done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  const PrivateKey = require('../../key/private');
  const pk = new PrivateKey(new _nodeV2());
  return pk.generate().then((err) => {
    if (err) { return done(err); }
    return done(null, pk);
  });
}


/***
 * symmetric
 *
 * generate a symmetric key for use with the protocol
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
_nodeV2.prototype.symmetric = sk;
function sk(cb) {
  const done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  const SymmetricKey = require('../../key/symmetric');
  const sk = new SymmetricKey(new _nodeV2());
  return sk.generate().then((err) => {
    if (err) { return done(err); }
    return done(null, sk);
  });
}


/***
 * sklength
 *
 * get symmetric key length
 *
 * @function
 * @api public
 *
 * @returns {Number}
 */
_nodeV2.prototype.sklength = sklength;
function sklength() {
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
 * @returns {Callback|Promise}
 */
_nodeV2.prototype.__encrypt = __encrypt;
function __encrypt(data, key, footer, nonce, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.protocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  return sodium.ready.then(() => {

    const header = utils.local(self);

    [ data, footer, nonce ] = (utils.parse('utf-8'))(data, footer, nonce);

    let token;
    try {
      token = aeadEncrypt(key, header, data, footer, nonce);
    } catch (ex) {
      return done(ex);
    }

    return done(null, token);
  });
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
 * @returns {Callback|Promise}
 */
_nodeV2.prototype.encrypt = encrypt;
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
 * @returns {Callback|Promise}
 */
_nodeV2.prototype.decrypt = decrypt;
function decrypt(token, key, footer, cb) {
  const self = this;
  const done = utils.ret(cb);

  if (!(key.protocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  return sodium.ready.then(() => {

    let payload, data, header = utils.local(self);
    try {
      [ header, payload, footer ] = decapsulate(header, token, footer);

      data = aeadDecrypt(key, header, payload, footer);
    } catch (ex) {
      return done(ex);
    }

    return done(null, data);
  });
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
 * @returns {Callback|Promise}
 */
_nodeV2.prototype.aeadEncrypt = aeadEncrypt;
function aeadEncrypt(key, header, plaintext, footer, nonce) {

  // build nonce

  const nlen   = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const nkey   = nonce || sodium.randombytes_buf(nlen);
  const _nonce = sodium.crypto_generichash(nlen, plaintext, nkey);

  nonce = Buffer.from(_nonce);

  // encrypt

  let ad;
  try {
    ad = utils.pae(header, nonce, footer);
  } catch (ex) {
    return done(ex);
  }

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
 * @returns {Callback|Promise}
 */
_nodeV2.prototype.aeadDecrypt = aeadDecrypt;
function aeadDecrypt(key, header, payload, footer) {

  // recover nonce

  const plen = Buffer.byteLength(payload);

  const nlen  = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const nonce = Buffer.from(payload).slice(0, nlen);

  // decrypt and verify

  let ad;
  try {
    ad = utils.pae(header, nonce, footer);
  } catch (ex) {
    return done(ex);
  }

  const ciphertext = Buffer.from(payload).slice(nlen, plen);

  const _plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key.raw());
  const plaintext  = Buffer.from(_plaintext);

  // format

  return plaintext.toString('utf-8');
}
