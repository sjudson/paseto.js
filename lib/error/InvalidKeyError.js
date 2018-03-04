const PasetoError = require('./PasetoError');

/***
 * InvalidKeyError
 *
 * Library error.
 *
 * @constructor
 * @api private
 */
function InvalidKeyError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'InvalidKeyError';
  this.message = message;
}

// extend base error
InvalidKeyError.prototype.__proto__ = PasteoError.prototype;

module.exports = InvalidKeyError;
