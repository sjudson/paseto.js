const crypto = require('crypto');
const sodium = require('libsodium-wrappers-sumo');

const PasetoError   = require('./error/PasetoError');
const EncodingError = require('./error/EncodingError');


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
 * prepare parser
 *
 * @function
 * @api private
 *
 * @param {String} as
 * @returns {Function}
 */
module.exports.parse = parse;
function parse(as) {

  if ([ 'hex', 'base64', 'utf-8' ].indexOf(as) === -1) { throw new Error('Unknown format'); }
  const parser = (as === 'base64') ? fromB64URLSafe : (i) => { return Buffer.from(i, as); }

  /***
   * `lambda`
   *
   * parse strings as provided format into buffer
   *
   * @function
   * @api private
   *
   * @returns {Array}
   */
  return function () {
    return [ ...arguments ].map((inp) => {
      if (!inp) { return Buffer.from(''); }

      try {
        return (inp instanceof Buffer) ? inp : parser(inp);
      } catch (ex) {
        throw new PasetoError('Invalid encoding detected');
      }
    });
  }
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
  const pieces = (parse('utf-8'))(...arguments);

  const LE64 = (n) => {
    // also guarantees that msb will be zero as required
    if (n > Number.MAX_SAFE_INTEGER) { throw new EncodingError('Message too long to encode'); }

    const up = ~~(n / 0xFFFFFFFF);
    const dn = (n % 0xFFFFFFFF) - up;

    let buf = Buffer.alloc(8);

    buf.writeUInt32LE(up, 4);
    buf.writeUInt32LE(dn, 0);

    return buf;
  }

  let accumulator = LE64(pieces.length);
  pieces.forEach((piece) => {
    let len = LE64(Buffer.byteLength(piece));
    accumulator = Buffer.concat([ accumulator, len, piece ]);
  });

  return accumulator;
}


/***
 * local
 *
 * build local header
 *
 * @function
 * @api private
 *
 * @param {Object} protocol
 * @returns {Buffer} header
 */
module.exports.local = local;
function local(protocol) {
  const ind = protocol.repr();
  return Buffer.from(ind + '.local.', 'utf-8');
}


/***
 * public
 *
 * build public header
 *
 * @function
 * @api private
 *
 * @param {Object} protocol
 * @returns {Buffer} header
 */
module.exports.public = public;
function public(protocol) {
  const ind = protocol.repr();
  return Buffer.from(ind + '.public.', 'utf-8');
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
    if (!promisify) { return void callback.apply(this, args); }

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
