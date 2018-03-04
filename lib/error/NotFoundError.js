const PasetoError = require('./PasetoError');

/***
 * NotFoundError
 *
 * Library error.
 *
 * @constructor
 * @api private
 */
function NotFoundError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'NotFoundError';
  this.message = message;
}

// extend base error
NotFoundError.prototype.__proto__ = PasteoError.prototype;

module.exports = NotFoundError;
