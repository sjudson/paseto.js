const PublicKey = require('./common');

const V1 = require('../../protocol/V1/browser');
const V2 = require('../../protocol/V2/browser');


/***
 * _browserPublicKey
 *
 * public key for asymmetric cryptography
 *
 * @constructor
 *
 * @api public
 *
 * @param {Object} protocol
 */
module.exports = _browserPublicKey;
function _browserPublicKey(protocol) {
  PublicKey.call(this, protocol);

  const self = this;
  protocol = protocol || new V2();

  self._protocol = protocol;
}
_browserPublicKey.super_ = PublicKey;
_browserPublicKey.prototype = Object.create(PublicKey.prototype, {
  constructor: { value: _browserPublicKey, enumerable: false, writeable: true }
});


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
PublicKey.V1 = v1;
function v1() {
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
PublicKey.V2 = v2;
function v2() {
  return new PublicKey(new V2());
}



/**************
 * Subclasses *
 **************/



/***
 * _browserPublicKeyV1
 *
 * subclass forcing use of V1
 *
 * @constructor
 * @api public
 */
module.exports.V1 = _browserPublicKeyV1;
function _browserPublicKeyV1() {
  _browserPublicKey.call(this, new V1());
}
_browserPublicKeyV1.prototype = Object.create(_browserPublicKey.prototype);
_browserPublicKeyV1.prototype.constructor = _browserPublicKeyV1;


/***
 * _browserPublicKeyV2
 *
 * subclass forcing use of V2
 *
 * @constructor
 * @api public
 */
module.exports.V2 = _browserPublicKeyV2;
function _browserPublicKeyV2() {
  _browserPublicKey.call(this, new V2());
}
_browserPublicKeyV2.prototype = Object.create(_browserPublicKey.prototype);
_browserPublicKeyV2.prototype.constructor = _browserPublicKeyV2;
