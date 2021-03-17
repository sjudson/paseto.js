const sodium = require('../../nacl/shim');

const V1    = require('../../protocol/V1/common');
const V2    = require('../../protocol/V2/common');
const utils = require('../../utils/common');


/***
 * PublicKey
 *
 * public key for asymmetric cryptography
 *
 * @constructor
 *
 * @api public
 *
 * @param {Object} protocol
 */
module.exports = PublicKey;
function PublicKey() {}


/***
 * inject
 *
 * complete construction asynchronously
 *
 * @function
 *
 * @api public
 *
 * @param {Buffer} rkey
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
PublicKey.prototype.inject = inject;
function inject(rkey, cb) {
  const self = this;
  const done = utils.ret(cb);

  return sodium.ready.then(() => {
    
    if (self.protocol() instanceof V2) {

      if (!(rkey instanceof Buffer)) { return done(new TypeError('Raw key must be provided as a buffer')); }

      const len = Buffer.byteLength(rkey);

      if (len !== sodium.crypto_sign_PUBLICKEYBYTES) {
        return done(new Error('Public keys must be 32 bytes long; ' + len + ' given.'));
      }
    }

    self._key = rkey;
    return done();
  });
}


/***
 * base64
 *
 * complete construction asynchronously using base64 encoded key
 *
 * @function
 *
 * @api public
 *
 * @param {Buffer} skey
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
PublicKey.prototype.base64 = base64;
function base64(skey, cb) {
  return this.inject(utils.fromB64URLSafe(skey), cb);
}


/***
 * hex
 *
 * complete construction asynchronously using hex encoded key
 *
 * @function
 *
 * @api public
 *
 * @param {Buffer} skey
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
PublicKey.prototype.hex = hex;
function hex(skey, cb) {
  return this.inject(Buffer.from(skey, 'hex'), cb);
}


/***
 * protocol
 *
 * return the underlying protocol object
 *
 * @function
 * @api public
 *
 * @returns {Object}
 */
PublicKey.prototype.protocol = protocol;
function protocol() {
  return this._protocol;
}


/***
 * encode
 *
 * encode the raw key as b64url
 *
 * @function
 * @api public
 *
 * @returns {String}
 */
PublicKey.prototype.encode = encode;
function encode() {
  return utils.toB64URLSafe(this._key);
}


/***
 * raw
 *
 * return the raw key buffer
 *
 * @function
 * @api public
 *
 * @returns {Buffer}
 */
PublicKey.prototype.raw = raw;
function raw() {
  return this._key;
}
