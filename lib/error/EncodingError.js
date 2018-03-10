const PasetoError = require('./PasetoError');

/***
 * EncodingError
 *
 * Library error.
 *
 * @constructor
 * @api private
 */
function EncodingError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'EncodingError';
  this.message = message;
}

// extend base error
EncodingError.prototype.__proto__ = PasetoError.prototype;

module.exports = EncodingError;
