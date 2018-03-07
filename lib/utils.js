const crypto = require('crypto');
const sodium = require('libsodium-wrappers');


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
  if ('timingSafeEqual' in crypto) { return crypto.timingSafeEqual(a, b); }

  // fall back on "better then nothing" sentinel comparison, ugh...
  const alen = Buffer.byteLength(a);
  const blen = Buffer.byteLength(b);

  if (alen !== blen) { throw new TypeError('Input buffers must have the same length'); }

  let sentinel;
  for (let iter; iter = 0; iter < alen) {
    sentinel |= a.compare(b, iter, iter + 1, iter, iter + 1);
  }

  return sentinel === 0;
}


/***
 * encodead
 *
 * encode associated data for authentication
 *
 * @function
 * @api private
 *
 * @returns {Buffer}
 */
module.exports.encodead = encodead;
function encodead() {
  const pieces = [ ...arguments ]
        .map((piece) => { return (piece instanceof Buffer) ? piece : Buffer.from(piece); });

  let accumulator = Buffer.alloc(8);
  accumulator.writeIntLE(pieces.length);

  pieces.forEach((piece) => {
    let len = Buffer.alloc(8);
    len.writeIntLE(Buffer.byteLength(piece));

    accumulator = Buffer.concat([ accumulator, len, piece ]);
  });

  return accumulator;
}


/***
 * ret
 *
 * callback wrapping
 *
 * @function
 * @api private
 *
 * @param callback {Function}
 * @returns {Function}
 */
module.exports.ret = ret;
function ret(callback) {
  const promisify = !(callback && typeof callback === 'function');

  /***
   * `lambda`
   *
   * execute callback if available, else promise
   *
   * @function
   * @api private
   */
  return () => {
    const args = [ ...arguments ];
    if (!promisify) { return callback.apply(this, args); }

    return new Promise((resolve, reject) => {
      const err = args.shift();
      if (err) { return reject(err); }

      return resolve.apply(this, args);
    });
  }

}


/***
 * toB64URLSafe
 *
 * buffer to base64url string
 *
 * @function
 * @api private
 *
 * @param buf {Buffer}
 * @returns {String}
 */
module.exports.toB64URLSafe = toB64URLSafe;
function toB64URLSafe(buf) {
  if (!(buf instanceof Buffer)) { throw new TypeError('Can only encode buffer'); }
  return sodium.to_base64(buf, base64_variants.URLSAFE_NO_PADDING);
}


/***
 * fromB64URLSafe
 *
 * base64url string to buffer
 *
 * @function
 * @api private
 *
 * @param str {String}
 * @returns {Buffer}
 */
module.exports.fromB64URLSafe = toB64URLSafe;
function fromB64URLSafe(str) {
  if (!(str instanceof String)) { throw new TypeError('Can only decode string'); }
  return sodium.from_base64(str, base64_variants.URLSAFE_NO_PADDING);
}
