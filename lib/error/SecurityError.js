const PasetoError = require('./PasetoError');

/***
 * SecurityError
 *
 * Library error.
 *
 * @constructor
 * @api private
 */
function SecurityError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'SecurityError';
  this.message = message;
}

// extend base error
SecurityError.prototype.__proto__ = PasteoError.prototype;

module.exports = SecurityError;
