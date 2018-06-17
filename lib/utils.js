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
  const pieces = [ ...arguments ];

  let accumulator = Buffer.alloc(8);
  accumulator.writeIntLE(pieces.length);

  pieces.forEach((piece) => {
    let len = Buffer.alloc(8);
    len.writeIntLE(Buffer.byteLength(piece));

    accumulator = Buffer.concat([ accumulator, len, piece ]);
  });

  return accumulator;
}


// isolate out header and footer handling
module.exports.header = {};
module.exports.footer = {};


/***
 * header.local
 *
 * build local header
 *
 * @function
 * @api private
 *
 * @param {Object} protocol
 * @returns {Buffer} header
 */
module.exports.header.local = local;
function local(protocol) {
  const ind = protocol.repr();
  return Buffer.from(ind + '.local.', 'utf-8');
}


/***
 * header.public
 *
 * build public header
 *
 * @function
 * @api private
 *
 * @param {Object} protocol
 * @returns {Buffer} header
 */
module.exports.header.public = public;
function public(protocol) {
  const ind = protocol.repr();
  return Buffer.from(ind + '.public.', 'utf-8');
}


/***
 * header.validate
 *
 * validate (and remove) header
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @param {Buffer} header
 * @returns {String} token
 */
module.exports.header.validate = hvalidate;
function hvalidate(token, header) {
  const parsed = Buffer.from(token, 'utf-8');

  const hlen    = Buffer.byteLength(header);
  const leading = parsed.slice(0, hlen);

  if (!cnstcomp(header, leading)) { throw new Error('Invalid message header'); }

  return parsed.slice(hlen).toString('utf-8');
}


/***
 * footer.extract
 *
 * extract footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @returns {Buffer} footer
 */
module.exports.footer.extract = extract;
function extract(token) {
  const pieces = token.split('.');

  return (pieces.length > 3)
    ? fromB64URLSafe(pieces.pop())
    : Buffer.from('');
};


/***
 * footer.remove
 *
 * remove footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @returns {String} token
 */
module.exports.footer.remove = remove;
function remove(token) {
  const pieces = token.split('.');

  return (pieces.length > 3)
    ? pieces.slice(0, 3).join('.')
    : token;
};


/***
 * footer.validate
 *
 * validate (and remove) footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @param {Buffer} footer
 * @returns {String} token
 */
module.exports.footer.validate = fvalidate;
function fvalidate(token, footer) {
  if (!footer) { return token; }
  footer = Buffer.concat([ Buffer.from('.', 'utf-8'), footer ]);

  const trailing = Buffer.concat([ Buffer.from('.', 'utf-8'), extract(token) ]);

  if (!cnstcomp(footer, trailing)) { throw new Error('Invalid message footer'); }

  return remove(token);
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
