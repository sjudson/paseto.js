const crypto = require('crypto');

const utils               = require('../utils');
const PasetoError         = require('../error/PasetoError');
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
  this._header = 'v1';

  this.constants = {
    CIPHER_MODE: 'aes-256-ctr',
    HASH_ALGO:   'sha384',
    NONCE_SIZE:  32,
    MAC_SIZE:    48
  }
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
V1.prototype.header = header;
function header() {
  return this._header;
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
V1.prototype.__encrypt = __encrypt;
function __encrypt(data, key, footer, nonce, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  const header = self.header();
  let prefix = header + '.local.';

  [ prefix, data, footer, nonce ] = utils.parse(prefix, data, footer, nonce);

  return self.aeadEncrypt(key, prefix, data, footer, nonce)
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
 * @returns {String} token
 */
V1.prototype.encrypt = encrypt;
function encrypt(data, key, footer, cb) {
  return this.__encrypt(data, key, footer, '', cb);
}


/***
 * defnonce
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
V1.prototype.defnonce = defnonce;
function defnonce(mess, nkey) {
  const self = this;
  return crypto.createHmac(self.constants.HASH_ALGO, nkey).update(mess).digest().slice(0, 32);
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
V1.prototype.aeadEncrypt = aeadEncrypt;
function aeadEncrypt(key, prefix, plaintext, footer, nonce) {
  const self = this;

  return new Promise((resolve, reject) => {
    nonce = (!!nonce)
      ? self.defnonce(plaintext, nonce)
      : self.defnonce(plaintext, crypto.randomBytes(self.constants.NONCE_SIZE));

    key.split(nonce.slice(0, 16), (err, keys) => {
      if (err) { return reject(err); }
      const [ enckey, authkey ] = keys;

      const encryptor  = crypto.createCipheriv(self.constants.CIPHER_MODE, enckey, nonce.slice(16, 32));
      const ciphertext = Buffer.concat([ encryptor.update(plaintext), encryptor.final() ]);

      // an empty buffer is truthy, if no plaintext
      if (!ciphertext) { return reject(new PasetoError('Encryption failed.')); }

      const payload = utils.pae(prefix, nonce, ciphertext, footer);

      const authenticator = crypto.createHmac(self.constants.HASH_ALGO, authkey);
      const mac           = authenticator.update(payload).digest();

      const token = prefix.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([ nonce, ciphertext, mac ]));

      return (!Buffer.byteLength(footer))
        ? resolve(token)
        : resolve(token + '.' + utils.toB64URLSafe(footer));
    });
  });
}
