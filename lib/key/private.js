const sodium = require('libsodium-wrappers');

const V1        = require('../protocol/V1');
const V2        = require('../protocol/V2');
const utils     = require('../utils');
const PublicKey = require('./public');


// patch
sodium.crypto_sign_KEYPAIRBYTES = sodium.crypto_sign_SECRETKEYBYTES + sodium.crypto_sign_PUBLICKEYBYTES;


/***
 * AsymmetricSecretKey
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
module.exports = AsymmetricSecretKey;
function AsymmetricSecretKey(rkey, protocol) {
  const self = this;
  protocol = protocol || new V2();

  if (protocol instanceof V2) {
    const len = Buffer.byteLength(rkey);

    if (len === sodium.crypto_sign_KEYPAIRBYTES) {
      rkey = rkey.slice(0, sodium.crypto_sign_SECRETKEYBYTES);
    } else if (len !== sodium.crypto_sign_SECRETKEYBYTES) {

      if (len !== sodium.crypto_sign_SEEDBYTES) {
        throw new Error('Secret keys must be 32 or 64 bytes long; ' + len + ' given.')
      }

      rkey = sodium.crypto_sign_seed_keypair(rkey).privateKey;
    }
  }

  self.key      = rkey;
  self.protocol = protocol;
}


/***
 * generate
 *
 * syntactic sugar for constructor generating random key
 *
 * @function
 * @api public
 *
 * @param {Object} protocol
 *
 * @returns {AsymmetricSecretKey}
 */
AsymmetricSecretKey.generate = generate;
function generate(protocol) {
  protocol = protocol || new V2();

  // if (protocol instanceof V1) {};

  return new AsymmetricSecretKey(sodium.crypto_sign_keypair.privateKey, protocol);
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
 * @returns {AsymmetricSecretKey}
 */
AsymmetricSecretKey.v1 = v1;
function v1(rkey) {
  return new AsymmetricSecretKey(rkey, new V1());
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
 * @returns {AsymmetricSecretKey}
 */
AsymmetricSecretKey.v2 = v2;
function v2(rkey) {
  return new AsymmetricSecretKey(rkey, new V2());
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
 * @returns {AsymmetricSecretKey}
 */
AsymmetricSecretKey.fromEncodedString = fromEncodedString;
function fromEncodedString(skey, protocol) {
  return new AsymmetricSecretKey(utils.fromB64URLSafe(skey), protocol);
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
AsymmetricSecretKey.prototype.encode = encode;
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
AsymmetricSecretKey.prototype.getProtocol = getProtocol;
function getProtocol() {
  return this.protocol;
}


/***
 * getPublicKey
 *
 * return the corresponding public key object
 *
 * @function
 * @api public
 *
 * @returns {Object}
 */
AsymmetricSecretKey.prototype.getPublicKey = getPublicKey;
function getPublicKey() {
  const self = this;

  // if (self.protocol instanceof V1) {};

  return new PublicKey(crypto_sign_ed25519_sk_to_pk(self.key), self.protocol);
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
AsymmetricSecretKey.prototype.raw = raw;
function raw() {
  return this.key;
}



/**************
 * Subclasses *
 **************/



/***
 * AsymmetricSecretKeyV1
 *
 * subclass forcing use of v1
 *
 * @constructor
 * @api public
 *
 * @param {Buffer} rkey
 */
module.exports.V1 = AsymmetricSecretKeyV1;
function AsymmetricSecretKeyV1(rkey) {
  AsymmetricSecretKey.call(this, rkey, new V1());
}
AsymmetricSecretKeyV1.prototype = Object.create(AsymmetricSecretKey.prototype);
AsymmetricSecretKeyV1.prototype.constructor = AsymmetricSecretKeyV1;


/***
 * AsymmetricSecretKeyV2
 *
 * subclass forcing use of v2
 *
 * @constructor
 * @api public
 *
 * @param {Buffer} rkey
 */
module.exports.V2 = AsymmetricSecretKeyV2;
function AsymmetricSecretKeyV2(rkey) {
  AsymmetricSecretKey.call(this, rkey, new V2());
}
AsymmetricSecretKeyV2.prototype = Object.create(AsymmetricSecretKey.prototype);
AsymmetricSecretKeyV2.prototype.constructor = AsymmetricSecretKeyV2;
