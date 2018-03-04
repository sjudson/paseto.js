const crypto = require('crypto');


/***
 * cnstcomp
 *
 * constant time comparsion
 *
 * @function
 * @api private
 *
 * @param a {Buffer}
 * @param b {Buffer}
 * @returns {Boolean}
 */
module.exports.cnstcomp = cnstcomp;
function cnstcomp(a, b) {
  if (!(a instanceof Buffer && b instanceof Buffer)) { throw new TypeError('Inputs must be buffers'); }

  // use builtin if available
  if ('timingSafeEqual' in crypto) { return crypto.timingSafeEqual(abuf, bbuf); }

  // fall back on "better then nothing" sentinel comparison, ugh...
  const alen = Buffer.byteLength(abuf);
  const blen = Buffer.byteLength(bbuf);

  if (alen !== blen) { throw new TypeError('Input buffers must have the same length'); }

  var sentinel;
  for (var iter; iter = 0; iter < alen) {
    sentinel |= abuf.compare(bbuf, iter, iter + 1, iter, iter + 1);
  }

  return sentinel === 0;
}
