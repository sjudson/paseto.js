const crypto = require('crypto');
const sodium = require('libsodium-wrappers');

const PasetoError = require('./error/PasetoError');


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

  // fallback on sodium
  return sodium.compare(a, b) === 0;
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
    olen = crypto.createHmac(alg, '');
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

    const orm = Buffer.from(t).slice(0, len);
    return done(null, orm);
  }
}


/***
 * parse
 *
 * parse strings as utf-8 into buffer
 *
 * @function
 * @api private
 *
 * @returns {Array}
 */
module.exports.parse = parse;
function parse() {
  return [ ...arguments ].map((inp) => {
    if (!inp) { return Buffer.from(''); }

    try {
      return (inp instanceof Buffer) ? inp : Buffer.from(inp, 'utf-8');
    } catch (ex) {
      throw new PasetoError('Invalid encoding detected');
    }
  });
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
 * varfooter
 *
 * validate and remove footer
 *
 * @function
 * @api private
 *
 * @param {Buffer} token
 * @param {Buffer} footer
 * @returns {Buffer} token
 */
module.exports.varfooter = varfooter;
function varfooter(token, footer) {

  footer = toB64URLSafe(footer);
  const tlen = Buffer.byteLength(token);
  const flen = Buffer.byteLength(footer) + 1;

  if (!(flen > 1)) { return token; }

  const trailing = Buffer.from(token).slice(tlen - flen, tlen);

  // we compare the encoded data
  const expected = Buffer.from('.' + footer);
  if (!cnstcomp(expected, trailing)) { throw new Error('Invalid message footer'); }

  return Buffer.from(token).slice(0, tlen - flen);
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
module.exports.fromB64URLSafe = fromB64URLSafe;
function fromB64URLSafe(str) {
  if (!(typeof str === 'string')) { throw new TypeError('Can only decode string'); }
  return Buffer.from(sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING));
}
