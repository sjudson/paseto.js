const PasetoError = require('./PasetoError');

/***
 * InvalidPurposeError
 *
 * Library error.
 *
 * @constructor
 * @api private
 */
function InvalidPurposeError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'InvalidPurposeError';
  this.message = message;
}

// extend base error
InvalidPurposeError.prototype.__proto__ = PasetoError.prototype;

module.exports = InvalidPurposeError;
