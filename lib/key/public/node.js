const PublicKey = require('./common');

const V1 = require('../../protocol/V1/node');
const V2 = require('../../protocol/V2/node');


/***
 * _nodePublicKey
 *
 * public key for asymmetric cryptography
 *
 * @constructor
 *
 * @api public
 *
 * @param {Object} protocol
 */
module.exports = _nodePublicKey;
function _nodePublicKey(protocol) {
  PublicKey.call(this, protocol);

  const self = this;
  protocol = protocol || new V2();

  self._protocol = protocol;
}
_nodePublicKey.super_ = PublicKey;
_nodePublicKey.prototype = Object.create(PublicKey.prototype, {
  constructor: { value: _nodePublicKey, enumerable: false, writeable: true }
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
 * _nodePublicKeyV1
 *
 * subclass forcing use of V1
 *
 * @constructor
 * @api public
 */
module.exports.V1 = _nodePublicKeyV1;
function _nodePublicKeyV1() {
  _nodePublicKey.call(this, new V1());
}
_nodePublicKeyV1.prototype = Object.create(_nodePublicKey.prototype);
_nodePublicKeyV1.prototype.constructor = _nodePublicKeyV1;


/***
 * _nodePublicKeyV2
 *
 * subclass forcing use of V2
 *
 * @constructor
 * @api public
 */
module.exports.V2 = _nodePublicKeyV2;
function _nodePublicKeyV2() {
  _nodePublicKey.call(this, new V2());
}
_nodePublicKeyV2.prototype = Object.create(_nodePublicKey.prototype);
_nodePublicKeyV2.prototype.constructor = _nodePublicKeyV2;
