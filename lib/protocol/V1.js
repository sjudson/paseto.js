const crypto = require('crypto');

const extcrypto           = require('../../extcrypto');
const utils               = require('../utils');
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
  this._header = 'v1';

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
 * generateSymmetricKey
 *
 * generate a symmetric key for use with the protocol
 *
 * @function
 * @api public
 *
 * @returns {SymmetricKey}
 */
V1.generateSymmetricKey = generateSymmetricKey;
function generateSymmetricKey() {
  // minor hack to mimic php api without circular dependency - probably a better way to do this
  // return require('../key/symmetric').generate(new V1());
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
 * getSymmetricKeyByteLength
 *
 * get symmetric length
 *
 * @function
 * @api public
 *
 * @returns {Number}
 */
V1.prototype.getSymmetricKeyByteLength = getSymmetricKeyByteLength;
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
V1.prototype.__encrypt = __encrypt;
function __encrypt(data, key, footer, nonce, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

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
V1.prototype.decrypt = decrypt
function decrypt(token, key, footer, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  const header = self.header();
  let prefix = header + '.local.';

  // parses as utf-8, we'll handle as base64url manually
  [ prefix, token, footer ] = utils.parse(prefix, token, footer);

  return self.aeadDecrypt(key, prefix, utils.varfooter(token, footer), footer)
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
 * @returns {String} token
 */
V1.prototype.sign = sign;
function sign(data, key, footer, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  const header = self.header();
  let prefix = header + '.public.';

  [ prefix, data, footer ] = utils.parse(prefix, data, footer);

  // sign

  // despite appearances, will use RSA-PSS w/ SHA384 and MGF1-SHA384.
  const payload = utils.pae(prefix, data, footer);
  const signer  = crypto.createSign('SHA384');
  signer.update(payload);

  const signature = signer.sign({ key: key.raw(), padding: crypto.constants.RSA_PKCS1_PSS_PADDING });

  // format

  const token = prefix.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([ data, signature ]));

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
V1.prototype.verify = verify;
function verify(token, key, footer, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.getProtocol() instanceof V1)) {
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
  const verifier = crypto.createVerify('SHA384');
  verify.update(expected);

  const valid = verifier.verify({ key: key.raw(), padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, signature);

  if (!valid) { return done(new PasetoError('Invalid signature for this message')); }

  // format

  return done(null, data.toString('utf-8'));
}


/***
 * RsaGetPublicKey
 *
 * get public key from private key
 *
 * @function
 * @ignore
 *
 * @param {String} sk
 * @returns {String} pk
 */
V1.prototype.RsaGetPublicKey = RsaGetPublicKey;
function RsaGetPublicKey(sk) {
  return extcrypto.extract(sk);
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
      : self.defnonce(plaintext, crypto.randomBytes(self._constants.NONCE_SIZE));

    key.split(nonce.slice(0, 16), (err, keys) => {
      if (err) { return reject(err); }
      const [ enckey, authkey ] = keys;

      const encryptor  = crypto.createCipheriv(self._constants.CIPHER_MODE, enckey, nonce.slice(16, 32));
      const ciphertext = Buffer.concat([ encryptor.update(plaintext), encryptor.final() ]);

      // an empty buffer is truthy, if no plaintext
      if (!ciphertext) { return reject(new PasetoError('Encryption failed.')); }

      const payload = utils.pae(prefix, nonce, ciphertext, footer);

      const authenticator = crypto.createHmac(self._constants.HASH_ALGO, authkey);
      const mac           = authenticator.update(payload).digest();

      const token = prefix.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([ nonce, ciphertext, mac ]));

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
 * @param {Buffer} prefix
 * @param {Buffer} token
 * @param {Buffer} footer
 * @returns {String} plaintext
 */
V1.prototype.aeadDecrypt = aeadDecrypt;
function aeadDecrypt(key, prefix, token, footer) {
  const self = this;

  return new Promise((resolve, reject) => {

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
      return reject(new PasetoError('Invalid encoding detected'));
    }

    const mlen = Buffer.byteLength(decoded);

    // recover nonce

    const nlen  = self._constants.NONCE_SIZE;
    const nonce = Buffer.from(decoded).slice(0, nlen);

    // decrypt and verify

    const ciphertext = Buffer.from(decoded).slice(nlen, mlen - self._constants.MAC_SIZE);
    const mac        = Buffer.from(decoded).slice(mlen - self._constants.MAC_SIZE);

    key.split(nonce.slice(0, 16), (err, keys) => {
      if (err) { return reject(err); }
      const [ enckey, authkey ] = keys;

      const payload = utils.pae(prefix, nonce, ciphertext, footer);

      const authenticator = crypto.createHmac(self._constants.HASH_ALGO, authkey);
      const calc          = authenticator.update(payload).digest();

      if (!utils.cnstcomp(mac, calc)) { return new SecurityError('Invalid MAC for given ciphertext.'); }

      const decryptor  = crypto.createDecipheriv(self._constants.CIPHER_MODE, enckey, nonce.slice(16, 32));
      const _plaintext = Buffer.concat([ decryptor.update(ciphertext), decryptor.final() ]);
      const plaintext  = Buffer.from(_plaintext);

      // an empty buffer is truthy, if no ciphertext
      if (!plaintext) { return reject(new PasetoError('Encryption failed.')); }

      // format

      return resolve(plaintext.toString('utf-8'));
    });
  });
}
