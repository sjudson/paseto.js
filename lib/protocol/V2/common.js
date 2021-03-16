const sodium = require('libsodium-wrappers-sumo');

const utils       = require('../../utils/common')
const decapsulate = require('../../decapsulate');

const PasetoError         = require('../../error/PasetoError');
const InvalidVersionError = require('../../error/InvalidVersionError');


/***
 * V2
 *
 * protocol version 2
 *
 * @constructor
 * @api public
 */
module.exports = V2;
function V2() {
  this._repr = 'v2';
}


/***
 * repr
 *
 * get protocol representation
 *
 * @function
 * @api public
 *
 * @returns {String}
 */
V2.prototype.repr = repr;
function repr() {
  return this._repr;
}


/***
 * sign
 *
 * asymmetric authentication
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} data
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V2.prototype.sign = sign;
function sign(data, key, footer, cb) {
  footer = footer || '';

  const self = this;
  const done = utils.ret(cb);

  if (!(key.protocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  return sodium.ready.then(() => {

    const header = utils.public(self);

    [ data, footer ] = (utils.parse('utf-8'))(data, footer);

    // sign

    let payload;
    try {
      payload = utils.pae(header, data, footer);
    } catch (ex) {
      return done(ex);
    }

    const _signature = sodium.crypto_sign_detached(payload, key.raw());
    const signature  = Buffer.from(_signature);

    // format

    const token = header.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([ data, signature ]));

    return (!Buffer.byteLength(footer))
      ? done(null, token)
      : done(null, token + '.' + utils.toB64URLSafe(footer));
  });
}


/***
 * verify
 *
 * asymmetric authentication
 *
 * @function
 * @api public
 *
 * @param {String} token
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V2.prototype.verify = verify;
function verify(token, key, footer, cb) {
  const self = this;
  const done = utils.ret(cb);

  if (!(key.protocol() instanceof V2)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  return sodium.ready.then(() => {

    let payload, header = utils.public(self);
    try {
      [ header, payload, footer ] = decapsulate(header, token, footer);
    } catch (ex) {
      return done(ex);
    }

    // recover data

    const plen = Buffer.byteLength(payload);

    const data      = Buffer.from(payload).slice(0, plen - sodium.crypto_sign_BYTES);
    const signature = Buffer.from(payload).slice(plen - sodium.crypto_sign_BYTES);

    // verify signature

    let expected;
    try {
      expected = utils.pae(header, data, footer);
    } catch (ex) {
      return done(ex);
    }

    const valid = sodium.crypto_sign_verify_detached(signature, expected, key.raw());

    if (!valid) { return done(new PasetoError('Invalid signature for this message')); }

    // format

    return done(null, data.toString('utf-8'));
  });
}
