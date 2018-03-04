/***
 * PasetoError
 *
 * Library error.
 *
 * @constructor
 * @api private
 */
function PasetoError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'PasetoError';
  this.message = message;
}

// extend generic error
PasetoError.prototype.__proto__ = Error.prototype;

module.exports = PasetoError;
