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
 * @param {Buffer} a
 * @param {Buffer} b
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
 * hkdf
 *
 * build an hkdf
 *
 * @function
 * @api private
 *
 * @param {String} alg
 * @returns {Function}
 */
module.exports.hkdf = hkdf;
function hkdf(alg) {

  let olen;
  try {
    olen = crypto.createHmac(alg, '').update('').digest('base64');
  } catch (ex) {
    throw new Error('Unable to configure HKDF.');
  }

  /***
   * `lambda`
   *
   * execute an hkdf
   *
   * @function
   * @api private
   *
   * @param {Buffer} key
   * @param {Buffer} salt
   * @param {Number} len
   * @param {String} use
   * @param {Function} done
   * @returns {Buffer}
   */
  return (key, salt, len, use, done) => {

    if (!len || len < 0 || len > 255 * olen) {
      return done(new Error('Bad output length requested of HKDF.'));
    }

    // if salt not provided, set it to a string of zeroes.
    if (!salt) { salt = Buffer.alloc(olen).fill(0); }

    const prk = crypto.createHmac(alg, salt).update(key).digest();

    if (Buffer.byteLength(prk) < olen) {
      return done(new Error('An unexpected condition occurred in the HKDF internals'));
    }

    const u = Buffer.from(use);

    let t  = Buffer.from('');
    let lb = Buffer.from('');
    let i, ibp;

    for (let bi = 1; Buffer.byteLength(t) < len; ++i) {
      i   = Buffer.from(String.fromCharCode(bi));
      inp = Buffer.concat([ lb, u, i ]);

      lb = crypto.createHmac(alg, prk).update(inp).digest();
      t  = Buffer.concat([ t, lb ]);
    }

    const orm = Buffer.from(t, 0, len);
    return done(null, orm);
  }
}


/***
 * parse
 *
 * parse strings as buffer
 *
 * @function
 * @api private
 *
 * @returns {Array}
 */
module.exports.parse = parse;
function parse() {
  return [ ...arguments ].map((inp) => { return (inp instanceof Buffer) ? inp : Buffer.from(inp); })
}


/***
 * pae
 *
 * encode associated data for authentication
 *
 * @function
 * @api private
 *
 * @returns {Buffer}
 */
module.exports.pae = pae;
function pae() {
  const pieces = parse(...arguments);

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
 * @param {Function} callback
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
  return function() {
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
 * @param {Buffer} buf
 * @returns {String}
 */
module.exports.toB64URLSafe = toB64URLSafe;
function toB64URLSafe(buf) {
  if (!(buf instanceof Buffer)) { throw new TypeError('Can only encode buffer'); }
  return sodium.to_base64(buf, sodium.base64_variants.URLSAFE_NO_PADDING);
}


/***
 * fromB64URLSafe
 *
 * base64url string to buffer
 *
 * @function
 * @api private
 *
 * @param {String} str
 * @returns {Buffer}
 */
module.exports.fromB64URLSafe = toB64URLSafe;
function fromB64URLSafe(str) {
  if (!(str instanceof String)) { throw new TypeError('Can only decode string'); }
  return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);
}
