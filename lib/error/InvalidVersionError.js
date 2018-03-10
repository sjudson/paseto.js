const PasetoError = require('./PasetoError');

/***
 * InvalidVersionError
 *
 * Library error.
 *
 * @constructor
 * @api private
 */
function InvalidVersionError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'InvalidVersionError';
  this.message = message;
}

// extend base error
InvalidVersionError.prototype.__proto__ = PasetoError.prototype;

module.exports = InvalidVersionError;
