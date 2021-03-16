const utils = require('../../utils/common');


/***
 * V1
 *
 * protocol version 1
 *
 * @constructor
 * @api public
 */
module.exports = V1;
function V1() {
  this._repr = 'v1';

  this._constants = { SIGN_SIZE: 256 }
}


/***
 * private
 *
 * generate a private key for use with the protocol
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V1.prototype.private = pk;
function pk(cb) {
  const done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  const PrivateKey = require('../../key/private');
  const pk = new PrivateKey(new V1());
  return pk.generate().then((err) => {
    if (err) { return done(err); }
    return done(null, pk);
  });
}


/***
 * symmetric
 *
 * generate a symmetric key for use with the protocol
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V1.prototype.symmetric = sk;
function sk(cb) {
  const done = utils.ret(cb);

  // minor hack to mimic php api without circular dependency - probably a better way to do this
  const SymmetricKey = require('../../key/symmetric');
  const sk = new SymmetricKey(new V1());
  return sk.generate().then((err) => {
    if (err) { return done(err); }
    return done(null, sk);
  });
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
V1.prototype.repr = repr;
function repr() {
  return this._repr;
}
