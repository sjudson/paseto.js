const sodium = require('libsodium-wrappers');

const V1    = require('../protocol/V1');
const V2    = require('../protocol/V2');
const utils = require('../utils');


/***
 * AsymmetricPublicKey
 *
 * private key for asymmetric cryptography
 *
 * @constructor
 *
 * @api public
 *
 * @param {Buffer} rkey
 * @param {Object} protocol
 */
module.exports = AsymmetricPublicKey;
function AsymmetricPublicKey(rkey, protocol) {
  const self = this;
  protocol = protocol || new V2();

  if (protocol instanceof V2) {
    const len = Buffer.byteLength(rkey);

    if (len !== sodium.crypto_sign_PUBLICKEYBYTES) {
      throw new Error('Public keys must be 32 bytes long; ' + len + ' given.')
    }
  }

  self.key      = rkey;
  self.protocol = protocol;
}


/***
 * v1
 *
 * syntactic sugar for constructor forcing use of protocol v1
 *
 * @function
 * @api public
 *
 * @param {Buffer} rkey
 *
 * @returns {AsymmetricPublicKey}
 */
AsymmetricPublicKey.v1 = v1;
function v1(rkey) {
  return new AsymmetricPublicKey(rkey, new V1());
}


/***
 * v2
 *
 * syntactic sugar for constructor forcing use of protocol v2
 *
 * @function
 * @api public
 *
 * @param {Buffer} rkey
 *
 * @returns {AsymmetricPublicKey}
 */
AsymmetricPublicKey.v2 = v2;
function v2(rkey) {
  return new AsymmetricPublicKey(rkey, new V2());
}


/***
 * fromEncodedString
 *
 * syntactic sugar for constructor using encoded instead of raw key
 *
 * @function
 * @api public
 *
 * @param {String} skey
 * @param {Object} protocol
 *
 * @returns {AsymmetricPublicKey}
 */
AsymmetricPublicKey.fromEncodedString = fromEncodedString;
function fromEncodedString(skey, protocol) {
  return new AsymmetricPublicKey(utils.fromB64URLSafe(skey), protocol);
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
AsymmetricPublicKey.prototype.encode = encode;
function encode() {
  return utils.toB64URLSafe(this.key);
}


/***
 * getProtocol
 *
 * return the underlying protocol object
 *
 * @function
 * @api public
 *
 * @returns {Object}
 */
AsymmetricPublicKey.prototype.getProtocol = getProtocol;
function getProtocol() {
  return this.protocol;
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
AsymmetricPublicKey.prototype.raw = raw;
function raw() {
  return this.key;
}



/**************
 * Subclasses *
 **************/



/***
 * AsymmetricPublicKeyV1
 *
 * subclass forcing use of v1
 *
 * @constructor
 * @api public
 *
 * @param {Buffer} rkey
 */
module.exports.V1 = AsymmetricPublicKeyV1;
function AsymmetricPublicKeyV1(rkey) {
  AsymmetricPublicKey.call(this, rkey, new V1());
}
AsymmetricPublicKeyV1.prototype = Object.create(AsymmetricPublicKey.prototype);
AsymmetricPublicKeyV1.prototype.constructor = AsymmetricPublicKeyV1;


/***
 * AsymmetricPublicKeyV2
 *
 * subclass forcing use of v2
 *
 * @constructor
 * @api public
 *
 * @param {Buffer} rkey
 */
module.exports.V2 = AsymmetricPublicKeyV2;
function AsymmetricPublicKeyV2(rkey) {
  AsymmetricPublicKey.call(this, rkey, new V2());
}
AsymmetricPublicKeyV2.prototype = Object.create(AsymmetricPublicKey.prototype);
AsymmetricPublicKeyV2.prototype.constructor = AsymmetricPublicKeyV2;
