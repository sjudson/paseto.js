const V1          = require('./common');
const utils       = require('../../utils/browser');
const decapsulate = require('../../decapsulate');

const PasetoError         = require('../../error/PasetoError');
const SecurityError       = require('../../error/SecurityError');
const InvalidVersionError = require('../../error/InvalidVersionError');


/***
 * _nodeV1
 *
 * protocol version 1
 *
 * @constructor
 * @api public
 */
module.exports = _nodeV1;
function _nodeV1() {
  V1.call(this);
}
_nodeV1.super_ = V1;
_nodeV1.prototype = Object.create(V1.prototype, {
  constructor: { value: _nodeV1, enumerable: false, writeable: true }
});


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
 * @returns {Function|Callback}
 */
_nodeV1.prototype.verify = verify;
function verify(token, key, footer, cb) {
  const self = this;
  const done = utils.ret(cb);

  if (!(key.protocol() instanceof V1)) {
    return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
  }

  let payload, header = utils.public(self);
  try {
    [ header, payload, footer ] = decapsulate(header, token, footer);
  } catch (ex) {
    return done(ex);
  }

  // recover data

  const plen = Buffer.byteLength(payload);

  const data      = Buffer.from(payload).slice(0, plen - self._constants.SIGN_SIZE);
  const signature = Buffer.from(payload).slice(plen - self._constants.SIGN_SIZE);

  // verify signature

  let expected;
  try {
    expected = utils.pae(header, data, footer);
  } catch (ex) {
    return done(ex);
  }

  const skey = window.subtle.importKey('spki', utils.keystrip(key.raw()), { name: 'RSA-PSS', hash: 'SHA-384' }, true, [ 'verify' ]);
  
  return window.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, skey, signature, expected).then((valid) => {
    if (!valid) { return done(new PasetoError('Invalid signature for this message')); }

    // format
    return done(null, data.toString('utf-8'));
  });
}
