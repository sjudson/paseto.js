'use strict';

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var crypto = require('crypto');

var extcrypto = require('../../extcrypto');
var utils = require('../utils');
var decapsulate = require('../decapsulate');

var PasetoError = require('../error/PasetoError');
var SecurityError = require('../error/SecurityError');
var InvalidVersionError = require('../error/InvalidVersionError');

/***
 * V1
 *
 * protocol version 1
 *
 * @constructor
 * @api public
 */
module.exports = V1;
function V1() {
  this._repr = 'v1';

  this._constants = {
    SYMMETRIC_KEY_BYTES: 32,

    CIPHER_MODE: 'aes-256-ctr',
    HASH_ALGO: 'sha384',
    NONCE_SIZE: 32,
    MAC_SIZE: 48,
    SIGN_SIZE: 256
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
V1.prototype.private = pk;
function pk(cb) {
  var done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  var PrivateKey = require('../key/private');
  var pk = new PrivateKey(new V1());
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
V1.prototype.symmetric = sk;
function sk(cb) {
  var done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  var SymmetricKey = require('../key/symmetric');
  var sk = new SymmetricKey(new V1());
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
V1.prototype.repr = repr;
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
V1.prototype.sklength = sklength;
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
 * @returns {Function|Callback}
 */
V1.prototype.__encrypt = __encrypt;
function __encrypt(data, key, footer, nonce, cb) {
  footer = footer || '';

  var self = this;
  var done = utils.ret(cb);

  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  var header = utils.local(self);

  var _utils$parse = utils.parse('utf-8')(data, footer, nonce);

  var _utils$parse2 = _slicedToArray(_utils$parse, 3);

  data = _utils$parse2[0];
  footer = _utils$parse2[1];
  nonce = _utils$parse2[2];


  return self.aeadEncrypt(key, header, data, footer, nonce).then(function (token) {
    return done(null, token);
  }).catch(function (err) {
    return done(err);
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
 * @returns {Function|Callback}
 */
V1.prototype.encrypt = encrypt;
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
 * @returns {Function|Callback}
 */
V1.prototype.decrypt = decrypt;
function decrypt(token, key, footer, cb) {
  var self = this;
  var done = utils.ret(cb);

  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  var payload = void 0,
      header = utils.local(self);
  try {
    var _decapsulate = decapsulate(header, token, footer);

    var _decapsulate2 = _slicedToArray(_decapsulate, 3);

    header = _decapsulate2[0];
    payload = _decapsulate2[1];
    footer = _decapsulate2[2];
  } catch (ex) {
    return done(ex);
  }

  return self.aeadDecrypt(key, header, payload, footer).then(function (data) {
    return done(null, data);
  }).catch(function (err) {
    return done(err);
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
 * @returns {Function|Callback}
 */
V1.prototype.sign = sign;
function sign(data, key, footer, cb) {
  footer = footer || '';

  var self = this;
  var done = utils.ret(cb);

  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  var header = utils.public(self);

  // sign

  var _utils$parse3 = utils.parse('utf-8')(data, footer);

  var _utils$parse4 = _slicedToArray(_utils$parse3, 2);

  data = _utils$parse4[0];
  footer = _utils$parse4[1];
  var payload = utils.pae(header, data, footer);
  var signer = crypto.createSign('SHA384');
  signer.update(payload);
  signer.end();

  var signature = signer.sign({ key: key.raw(), padding: crypto.constants.RSA_PKCS1_PSS_PADDING });

  // format

  var token = header.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([data, signature]));

  return !Buffer.byteLength(footer) ? done(null, token) : done(null, token + '.' + utils.toB64URLSafe(footer));
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
 * @returns {Function|Callback}
 */
V1.prototype.verify = verify;
function verify(token, key, footer, cb) {
  var self = this;
  var done = utils.ret(cb);

  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

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

  var data = Buffer.from(payload).slice(0, plen - self._constants.SIGN_SIZE);
  var signature = Buffer.from(payload).slice(plen - self._constants.SIGN_SIZE);

  // verify signature

  var expected = utils.pae(header, data, footer);
  var verifier = crypto.createVerify('SHA384');
  verifier.update(expected);
  verifier.end();

  var valid = verifier.verify({ key: key.raw(), padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, signature);

  if (!valid) {
    return done(new PasetoError('Invalid signature for this message'));
  }

  // format

  return done(null, data.toString('utf-8'));
}

/***
 * public
 *
 * get public key from private key
 *
 * @function
 * @ignore
 *
 * @param {String} sk
 * @returns {String} pk
 */
V1.prototype.public = gpublic;
function gpublic(sk) {
  return extcrypto.extract(sk);
}

/***
 * nonce
 *
 * nonce misuse defence
 *
 * @function
 * @api private
 *
 * @param {Buffer} mess
 * @param {Buffer} nkey
 * @returns {Buffer} nonce
 */
V1.prototype.nonce = nonce;
function nonce(mess, nkey) {
  var self = this;
  return crypto.createHmac(self._constants.HASH_ALGO, nkey).update(mess).digest().slice(0, 32);
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
 * @returns {Function|Callback}
 */
V1.prototype.aeadEncrypt = aeadEncrypt;
function aeadEncrypt(key, header, plaintext, footer, nonce) {
  var self = this;

  return new Promise(function (resolve, reject) {
    nonce = !!nonce ? self.nonce(plaintext, nonce) : self.nonce(plaintext, crypto.randomBytes(self._constants.NONCE_SIZE));

    key.split(nonce.slice(0, 16), function (err, keys) {
      if (err) {
        return reject(err);
      }

      var _keys = _slicedToArray(keys, 2),
          enckey = _keys[0],
          authkey = _keys[1];

      var encryptor = crypto.createCipheriv(self._constants.CIPHER_MODE, enckey, nonce.slice(16, 32));
      var ciphertext = Buffer.concat([encryptor.update(plaintext), encryptor.final()]);

      // an empty buffer is truthy, if no plaintext
      if (!ciphertext) {
        return reject(new PasetoError('Encryption failed.'));
      }

      var payload = utils.pae(header, nonce, ciphertext, footer);

      var authenticator = crypto.createHmac(self._constants.HASH_ALGO, authkey);
      var mac = authenticator.update(payload).digest();

      var token = header.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([nonce, ciphertext, mac]));

      return !Buffer.byteLength(footer) ? resolve(token) : resolve(token + '.' + utils.toB64URLSafe(footer));
    });
  });
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
 * @returns {Function|Callback}
 */
V1.prototype.aeadDecrypt = aeadDecrypt;
function aeadDecrypt(key, header, payload, footer) {
  var self = this;

  return new Promise(function (resolve, reject) {

    // recover nonce

    var plen = Buffer.byteLength(payload);

    var nlen = self._constants.NONCE_SIZE;
    var nonce = Buffer.from(payload).slice(0, nlen);

    // decrypt and verify

    var ciphertext = Buffer.from(payload).slice(nlen, plen - self._constants.MAC_SIZE);
    var mac = Buffer.from(payload).slice(plen - self._constants.MAC_SIZE);

    key.split(nonce.slice(0, 16), function (err, keys) {
      if (err) {
        return reject(err);
      }

      var _keys2 = _slicedToArray(keys, 2),
          enckey = _keys2[0],
          authkey = _keys2[1];

      var payload = utils.pae(header, nonce, ciphertext, footer);

      var authenticator = crypto.createHmac(self._constants.HASH_ALGO, authkey);
      var calc = authenticator.update(payload).digest();

      if (!utils.cnstcomp(mac, calc)) {
        return reject(new SecurityError('Invalid MAC for given ciphertext.'));
      }

      var decryptor = crypto.createDecipheriv(self._constants.CIPHER_MODE, enckey, nonce.slice(16, 32));
      var _plaintext = Buffer.concat([decryptor.update(ciphertext), decryptor.final()]);
      var plaintext = Buffer.from(_plaintext);

      // an empty buffer is truthy, if no ciphertext
      if (!plaintext) {
        return reject(new PasetoError('Decryption failed.'));
      }

      // format

      return resolve(plaintext.toString('utf-8'));
    });
  });
}