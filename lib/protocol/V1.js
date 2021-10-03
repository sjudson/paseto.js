const crypto = require('crypto');

const extcrypto   = require('../../extcrypto');
const utils       = require('../utils');
const decapsulate = require('../decapsulate');

const PasetoError         = require('../error/PasetoError');
const SecurityError       = require('../error/SecurityError');
const InvalidVersionError = require('../error/InvalidVersionError');


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
    HASH_ALGO:   'sha384',
    NONCE_SIZE:  32,
    MAC_SIZE:    48,
    SIGN_SIZE:   256
  }
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
  const done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  const PrivateKey = require('../key/private');
  const pk = new PrivateKey(new V1());
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
V1.prototype.symmetric = sk;
function sk(cb) {
  const done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  const SymmetricKey = require('../key/symmetric');
  const sk = new SymmetricKey(new V1());
  return sk.generate().then((err) => {
    if (err) { return done(err); }
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

  const self = this;
  const done = utils.ret(cb);

  if (key.purpose() !== 'local') {
    return done(new InvalidVersionError('The given key is not intended for local PASETO tokens.'));
  }
  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  const header = utils.local(self);

  [ data, footer, nonce ] = (utils.parse('utf-8'))(data, footer, nonce);

  return self.aeadEncrypt(key, header, data, footer, nonce)
    .then((token) => { return done(null, token); }).catch((err) => { return done(err); });
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
  const self = this;
  const done = utils.ret(cb);

  if (key.purpose() !== 'local') {
    return done(new InvalidVersionError('The given key is not intended for local PASETO tokens.'));
  }
  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  let payload, header = utils.local(self);
  try {
    [ header, payload, footer ] = decapsulate(header, token, footer);
  } catch (ex) {
    return done(ex);
  }

  return self.aeadDecrypt(key, header, payload, footer)
    .then((data) => { return done(null, data); }).catch((err) => { return done(err); });
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

  const self = this;
  const done = utils.ret(cb);

  if (key.purpose() !== 'public') {
    return done(new InvalidVersionError('The given key is not intended for local PASETO tokens.'));
  }
  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  const header = utils.public(self);

  [ data, footer ] = (utils.parse('utf-8'))(data, footer);

  // sign

  let payload;
  try {
    payload = utils.pae(header, data, footer);
  } catch (ex) {
    return done(ex);
  }

  const signer = crypto.createSign('SHA384');
  signer.update(payload);
  signer.end();

  const signature = signer.sign({ key: key.raw(), padding: crypto.constants.RSA_PKCS1_PSS_PADDING });

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
 * @returns {Function|Callback}
 */
V1.prototype.verify = verify;
function verify(token, key, footer, cb) {
  const self = this;
  const done = utils.ret(cb);

  if (key.purpose() !== 'public') {
    return done(new InvalidVersionError('The given key is not intended for local PASETO tokens.'));
  }
  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  let payload, header = utils.public(self);
  try {
    [ header, payload, footer ] = decapsulate(header, token, footer);
  } catch (ex) {
    return done(ex);
  }

  // recover data

  const plen = Buffer.byteLength(payload);

  const data      = Buffer.from(payload).slice(0, plen - self._constants.SIGN_SIZE);
  const signature = Buffer.from(payload).slice(plen - self._constants.SIGN_SIZE);

  // verify signature

  let expected;
  try {
    expected = utils.pae(header, data, footer);
  } catch (ex) {
    return done(ex);
  }

  const verifier = crypto.createVerify('SHA384');
  verifier.update(expected);
  verifier.end();

  const valid = verifier.verify({ key: key.raw(), padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, signature);

  if (!valid) { return done(new PasetoError('Invalid signature for this message')); }

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
  const self = this;
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
  const self = this;

  return new Promise((resolve, reject) => {
    nonce = (!!nonce)
      ? self.nonce(plaintext, nonce)
      : self.nonce(plaintext, crypto.randomBytes(self._constants.NONCE_SIZE));

    key.split(nonce.slice(0, 16), (err, keys) => {
      if (err) { return reject(err); }
      const [ enckey, authkey ] = keys;

      const encryptor  = crypto.createCipheriv(self._constants.CIPHER_MODE, enckey, nonce.slice(16, 32));
      const ciphertext = Buffer.concat([ encryptor.update(plaintext), encryptor.final() ]);

      // an empty buffer is truthy, if no plaintext
      if (!ciphertext) { return reject(new PasetoError('Encryption failed.')); }

      let payload;
      try {
        payload = utils.pae(header, nonce, ciphertext, footer);
      } catch (ex) {
        return done(ex);
      }

      const authenticator = crypto.createHmac(self._constants.HASH_ALGO, authkey);
      const mac           = authenticator.update(payload).digest();

      const token = header.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([ nonce, ciphertext, mac ]));

      return (!Buffer.byteLength(footer))
        ? resolve(token)
        : resolve(token + '.' + utils.toB64URLSafe(footer));
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
  const self = this;

  return new Promise((resolve, reject) => {

    // recover nonce

    const plen = Buffer.byteLength(payload);

    const nlen  = self._constants.NONCE_SIZE;
    const nonce = Buffer.from(payload).slice(0, nlen);

    // decrypt and verify

    const ciphertext = Buffer.from(payload).slice(nlen, plen - self._constants.MAC_SIZE);
    const mac        = Buffer.from(payload).slice(plen - self._constants.MAC_SIZE);

    key.split(nonce.slice(0, 16), (err, keys) => {
      if (err) { return reject(err); }
      const [ enckey, authkey ] = keys;

      let payload;
      try {
        payload = utils.pae(header, nonce, ciphertext, footer);
      } catch (ex) {
        return done(ex);
      }

      const authenticator = crypto.createHmac(self._constants.HASH_ALGO, authkey);
      const calc          = authenticator.update(payload).digest();

      if (!utils.cnstcomp(mac, calc)) { return reject(new SecurityError('Invalid MAC for given ciphertext.')); }

      const decryptor  = crypto.createDecipheriv(self._constants.CIPHER_MODE, enckey, nonce.slice(16, 32));
      const _plaintext = Buffer.concat([ decryptor.update(ciphertext), decryptor.final() ]);
      const plaintext  = Buffer.from(_plaintext);

      // an empty buffer is truthy, if no ciphertext
      if (!plaintext) { return reject(new PasetoError('Decryption failed.')); }

      // format

      return resolve(plaintext.toString('utf-8'));
    });
  });
}
