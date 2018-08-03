'use strict';

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var sodium = require('libsodium-wrappers-sumo');

var utils = require('../utils');
var decapsulate = require('../decapsulate');

var PasetoError = require('../error/PasetoError');
var InvalidVersionError = require('../error/InvalidVersionError');

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
  };
}

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
V2.prototype.private = pk;
function pk(cb) {
  var done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  var PrivateKey = require('../key/private');
  var pk = new PrivateKey(new V2());
  return pk.generate(function (err) {
    if (err) {
      return done(err);
    }
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
V2.prototype.symmetric = sk;
function sk(cb) {
  var done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  var SymmetricKey = require('../key/symmetric');
  var sk = new SymmetricKey(new V2());
  return sk.generate(function (err) {
    if (err) {
      return done(err);
    }
    return done(null, sk);
  });
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
 * sklength
 *
 * get symmetric key length
 *
 * @function
 * @api public
 *
 * @returns {Number}
 */
V2.prototype.sklength = sklength;
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
V2.prototype.__encrypt = __encrypt;
function __encrypt(data, key, footer, nonce, cb) {
  footer = footer || '';

  var self = this;
  var done = utils.ret(cb);

  if (!(key.protocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  return sodium.ready.then(function () {

    var header = utils.local(self);

    var _utils$parse = utils.parse('utf-8')(data, footer, nonce);

    var _utils$parse2 = _slicedToArray(_utils$parse, 3);

    data = _utils$parse2[0];
    footer = _utils$parse2[1];
    nonce = _utils$parse2[2];


    var token = void 0;
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
 * @returns {Callback|Promise}
 */
V2.prototype.decrypt = decrypt;
function decrypt(token, key, footer, cb) {
  var self = this;
  var done = utils.ret(cb);

  if (!(key.protocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  return sodium.ready.then(function () {

    var payload = void 0,
        data = void 0,
        header = utils.local(self);
    try {
      var _decapsulate = decapsulate(header, token, footer);

      var _decapsulate2 = _slicedToArray(_decapsulate, 3);

      header = _decapsulate2[0];
      payload = _decapsulate2[1];
      footer = _decapsulate2[2];


      data = aeadDecrypt(key, header, payload, footer);
    } catch (ex) {
      return done(ex);
    }

    return done(null, data);
  });
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
 * @returns {Callback|Promise}
 */
V2.prototype.sign = sign;
function sign(data, key, footer, cb) {
  footer = footer || '';

  var self = this;
  var done = utils.ret(cb);

  if (!(key.protocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  return sodium.ready.then(function () {

    var header = utils.public(self);

    // sign

    var _utils$parse3 = utils.parse('utf-8')(data, footer);

    var _utils$parse4 = _slicedToArray(_utils$parse3, 2);

    data = _utils$parse4[0];
    footer = _utils$parse4[1];
    var payload = utils.pae(header, data, footer);
    var _signature = sodium.crypto_sign_detached(payload, key.raw());
    var signature = Buffer.from(_signature);

    // format

    var token = header.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([data, signature]));

    return !Buffer.byteLength(footer) ? done(null, token) : done(null, token + '.' + utils.toB64URLSafe(footer));
  });
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
 * @returns {Callback|Promise}
 */
V2.prototype.verify = verify;
function verify(token, key, footer, cb) {
  var self = this;
  var done = utils.ret(cb);

  if (!(key.protocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  return sodium.ready.then(function () {

    var payload = void 0,
        header = utils.public(self);
    try {
      var _decapsulate3 = decapsulate(header, token, footer);

      var _decapsulate4 = _slicedToArray(_decapsulate3, 3);

      header = _decapsulate4[0];
      payload = _decapsulate4[1];
      footer = _decapsulate4[2];
    } catch (ex) {
      return done(ex);
    }

    // recover data

    var plen = Buffer.byteLength(payload);

    var data = Buffer.from(payload).slice(0, plen - sodium.crypto_sign_BYTES);
    var signature = Buffer.from(payload).slice(plen - sodium.crypto_sign_BYTES);

    // verify signature

    var expected = utils.pae(header, data, footer);
    var valid = sodium.crypto_sign_verify_detached(signature, expected, key.raw());

    if (!valid) {
      return done(new PasetoError('Invalid signature for this message'));
    }

    // format

    return done(null, data.toString('utf-8'));
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
V2.prototype.aeadEncrypt = aeadEncrypt;
function aeadEncrypt(key, header, plaintext, footer, nonce) {

  // build nonce

  var nlen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  var nkey = nonce || sodium.randombytes_buf(nlen);
  var _nonce = sodium.crypto_generichash(nlen, plaintext, nkey);

  nonce = Buffer.from(_nonce);

  // encrypt

  var ad = utils.pae(header, nonce, footer);
  var _ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key.raw());
  var ciphertext = Buffer.from(_ciphertext);

  // format

  var payload = Buffer.concat([nonce, ciphertext]);
  var token = header.toString('utf-8') + utils.toB64URLSafe(payload);

  return !Buffer.byteLength(footer) ? token : token + '.' + utils.toB64URLSafe(footer);
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
V2.prototype.aeadDecrypt = aeadDecrypt;
function aeadDecrypt(key, header, payload, footer) {

  // recover nonce

  var plen = Buffer.byteLength(payload);

  var nlen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  var nonce = Buffer.from(payload).slice(0, nlen);

  // decrypt and verify

  var ad = utils.pae(header, nonce, footer);
  var ciphertext = Buffer.from(payload).slice(nlen, plen);

  var _plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key.raw());
  var plaintext = Buffer.from(_plaintext);

  // format

  return plaintext.toString('utf-8');
}