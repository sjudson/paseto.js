const V2 = require('./common');

/***
 * _browserV2
 *
 * protocol version 2
 *
 * @constructor
 * @api public
 */
module.exports = _browserV2;
function _browserV2() {
  V2.call(this);
}
_browserV2.super_ = V2;
_browserV2.prototype = Object.create(V2.prototype, {
  constructor: { value: _browserV2, enumerable: false, writeable: true }
});
