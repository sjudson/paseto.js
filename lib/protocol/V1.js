const sodium = require('libsodium-wrappers');

const utils               = require('../utils');
const InvalidVersionError = require('../error/InvalidVersionError');


/***
 * V1
 *
 * protocol version 1
 *
 * @constructor
 * @api public
 */
module.exports = V1;
function V1() { this.header = 'v1'; }
