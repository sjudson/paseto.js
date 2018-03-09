const V1    = require('../protocol/V1');
const V2    = require('../protocol/V2');
const utils = require('../utils');


/***
 * SymmetricKeyV1
 *
 * subclass forcing use of v1
 *
 * @constructor
 * @api public
 *
 * @param rkey {Buffer}
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
 * @param rkey {Buffer}
 */
module.exports.V2 = SymmetricKeyV2;
function SymmetricKeyV2(rkey) {
  SymmetricKey.call(this, rkey, new V2());
}
SymmetricKeyV2.prototype = Object.create(SymmetricKey.prototype);
SymmetricKeyV2.prototype.constructor = SymmetricKeyV2;


/***
 * SymmetricKey
 *
 * secret key for symmetric cryptography
 *
 * @constructor
 * @api public
 *
 * @param rkey {Buffer}
 * @param protocol {Object}
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
 * encode
 *
 * encode the raw key as b64url
 *
 * @function
 * @api public
 *
 * @returns {String}
 */
SymmetricKey.prototype.encode = () => { return utils.toB64URLSafe(this.key); }


/***
 * fromEncodedString
 *
 * syntactic sugar for constructor using encoded instead of raw key
 *
 * @constructor
 * @api public
 *
 * @param skey {String}
 * @param protocol {Object}
 */
SymmetricKey.prototype.fromEncodedString = (skey, protocol) => {
  return new SymmetricKey(utils.fromB64URLSafe(skey, protocol));
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
SymmetricKey.prototype.getProtocol = () => { return this.protocol; }


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
SymmetricKey.prototype.raw = () => { return this.key; }


/***
 * split
 *
 * split into subkeys
 *
 * @function
 * @api public
 *
 * @params salt {Buffer}
 * @returns {Array}
 */
SymmetricKey.prototype.split = (salt) => {
  var self = this;

  const hkdf = utils.hkdf('sha384');

  const ekey = hkdf(self.key, 32, self.INFO_ENCRYPTION, salt);
  const akey = hkdf(self.key, 32, self.INFO_AUTHENTICATION, salt);

  return [ ekey, akey ];
}
