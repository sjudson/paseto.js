const sodium = require('libsodium-wrappers');

const registry = require('../registry');
const utils    = require('../utils');


/***
 * encrypt
 *
 * symmetric authenticated encryption
 *
 * @function
 * @api public
 *
 * @param data {Buffer}
 * @param key {Buffer}
 * @param footer {String}
 * @param cb {Function}
 * @returns token {String}
 */
function encrypt(data, key, footer, cb) {
  const done = utils.ret(cb);

  const header = registry.protocol.Version2.header;
  const prefix = header + '.local.';

  let token;
  try {
    token = aeadEncrypt(key, prefix, data, footer);
  } catch (ex) {
    return done(ex);
  }

  return done(null, token);
}


/***
 * aeadEncrypt
 *
 * internals of symmetric authenticated encryption
 *
 * @function
 * @api private
 *
 * @param key {Buffer}
 * @param prefix {Buffer}
 * @param plaintext {Buffer}
 * @param footer {String}
 * @returns token {String}
 */
function aeadEncrypt(key, prefix, plaintext, footer) {
  footer = footer || '';

  // build nonce

  const nlen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

  const _nonce = sodium.randombytes_buf(nlen);
  const nonce  = sodium.crypto_generichash(nlen, plaintext, _nonce);

  // encrypt

  const encryptor = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt;

  const ad         = utils.associate(prefix, plaintext, footer);
  const ciphertext = encryptor(plaintext, ad, nonce, key);

  // format

  const payload = Buffer.concat([ nonce, ciphertext ]);
  const token   = prefix + utils.toB64URLSafe(payload);

  return (!footer)
    ? token
    : token + '.' + utils.toB64URLSafe(footer);
}
