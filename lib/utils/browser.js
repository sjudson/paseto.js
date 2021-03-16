const common = require('./common');


module.exports = common;


/***
 * keystrip
 *
 * strip
 *
 * @function
 * @api private
 *
 * @param {String} pem
 * @returns {Buffer}
 */
module.exports.keystrip = keystrip;
function keystrip(pem) {
  const woprefix = pem.replace('-----BEGIN PUBLIC KEY-----', '');
  const wosuffix = pem.replace('-----END PUBLIC KEY-----',   '');

  return common.fromB64URLSafe(wosuffix);
}
