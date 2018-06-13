const sodium = require('libsodium-wrappers');

const V1    = require('../protocol/V1');
const V2    = require('../protocol/V2');
const utils = require('../utils');


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
function PublicKey(rkey, protocol) {
  const self = this;
  protocol = protocol || new V2();

  self._protocol = protocol;
}


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

    if (protocol instanceof V2) {
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
 * injectB64
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
PublicKey.prototype.injectB64 = injectB64;
function injectB64(skey, cb) {
  return this.inject(utils.fromB64URLSafe(skey), cb);
}


/***
 * V1
 *
 * syntactic sugar for constructor forcing use of protocol V1
 *
 * @function
 * @api public
 *
 * @returns {PublicKey}
 */
PublicKey.V1 = V1;
function V1() {
  return new PublicKey(new V1());
}


/***
 * V2
 *
 * syntactic sugar for constructor forcing use of protocol V2
 *
 * @function
 * @api public
 *
 * @returns {PublicKey}
 */
PublicKey.V2 = V2;
function V2() {
  return new PublicKey(new V2());
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



/**************
 * Subclasses *
 **************/



/***
 * PublicKeyV1
 *
 * subclass forcing use of V1
 *
 * @constructor
 * @api public
 */
module.exports.V1 = PublicKeyV1;
function PublicKeyV1() {
  PublicKey.call(this, new V1());
}
PublicKeyV1.prototype = Object.create(PublicKey.prototype);
PublicKeyV1.prototype.constructor = PublicKeyV1;


/***
 * PublicKeyV2
 *
 * subclass forcing use of V2
 *
 * @constructor
 * @api public
 */
module.exports.V2 = PublicKeyV2;
function PublicKeyV2() {
  PublicKey.call(this, new V2());
}
PublicKeyV2.prototype = Object.create(PublicKey.prototype);
PublicKeyV2.prototype.constructor = PublicKeyV2;
