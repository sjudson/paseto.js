const crypto = require('crypto');

const common = require('./common');


module.exports = common;


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
