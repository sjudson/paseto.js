const sodium = require('libsodium-wrappers');

const utils               = require('../utils');
const InvalidVersionError = require('../InvalidVersionError');


/***
 * V1
 *
 * protocol version 2
 *
 * @constructor
 * @api public
 */
module.exports = V1;
function V1() {
  self.header = 'v1';
}
