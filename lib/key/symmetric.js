const crypto = require('crypto');

const V1    = require('../protocol/V1');
const V2    = require('../protocol/V2');
const utils = require('../utils');


/***
 * SymmetricKey
 *
 * secret key for symmetric cryptography
 *
 * @constructor
 *
 * @api public
 *
 * @param {Buffer} rkey
 * @param {Object} protocol
 */
module.exports = SymmetricKey;
function SymmetricKey(rkey, protocol) {
  const self = this;

  self.INFO_ENCRYPTION     = 'paseto-encryption-key';
  self.INFO_AUTHENTICATION = 'paseto-auth-key-for-aead';

  self.key      = rkey;
  self.protocol = protocol || new V2();
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
 * @returns {SymmetricKey}
 */
SymmetricKey.generate = generate;
function generate(protocol) {
  protocol = protocol || new V2();
  return new SymmetricKey(crypto.randomBytes(protocol.getSymmetricKeyByteLength()), protocol);
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
 * @returns {SymmetricKey}
 */
SymmetricKey.v1 = v1;
function v1(rkey) {
  return new SymmetricKey(rkey, new V1());
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
 * @returns {SymmetricKey}
 */
SymmetricKey.v2 = v2;
function v2(rkey) {
  return new SymmetricKey(rkey, new V2());
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
 * @returns {SymmetricKey}
 */
SymmetricKey.fromEncodedString = fromEncodedString;
function fromEncodedString(skey, protocol) {
  return new SymmetricKey(utils.fromB64URLSafe(skey), protocol);
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
SymmetricKey.prototype.encode = encode;
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
SymmetricKey.prototype.getProtocol = getProtocol;
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
SymmetricKey.prototype.raw = raw;
function raw() {
  return this.key;
}


/***
 * split
 *
 * split into subkeys
 *
 * @function
 * @api private
 *
 * @param {Buffer} salt
 * @param {Function} done
 * @returns {Array}
 */
SymmetricKey.prototype.split = split;
function split(salt, done) {
  const self = this;
  const hkdf = utils.hkdf('sha384');

  hkdf(self.key, salt, 32, self.INFO_ENCRYPTION, (err, ekey) => {
    if (err) { return done(err); }

    hkdf(self.key, salt, 32, self.INFO_AUTHENTICATION, (err, akey) => {
      if (err) { return done(err); }
      return done(null, [ ekey, akey ]);
    });
  });
}



/**************
 * Subclasses *
 **************/



/***
 * SymmetricKeyV1
 *
 * subclass forcing use of v1
 *
 * @constructor
 * @api public
 *
 * @param {Buffer} rkey
 */
module.exports.V1 = SymmetricKeyV1;
function SymmetricKeyV1(rkey) {
  SymmetricKey.call(this, rkey, new V1());
}
SymmetricKeyV1.prototype = Object.create(SymmetricKey.prototype);
SymmetricKeyV1.prototype.constructor = SymmetricKeyV1;


/***
 * SymmetricKeyV2
 *
 * subclass forcing use of v2
 *
 * @constructor
 * @api public
 *
 * @param {Buffer} rkey
 */
module.exports.V2 = SymmetricKeyV2;
function SymmetricKeyV2(rkey) {
  SymmetricKey.call(this, rkey, new V2());
}
SymmetricKeyV2.prototype = Object.create(SymmetricKey.prototype);
SymmetricKeyV2.prototype.constructor = SymmetricKeyV2;
