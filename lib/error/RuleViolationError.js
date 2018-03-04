const PasetoError = require('./PasetoError');

/***
 * RuleViolationError
 *
 * Library error.
 *
 * @constructor
 * @api private
 */
function RuleViolationError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'RuleViolationError';
  this.message = message;
}

// extend base error
RuleViolationError.prototype.__proto__ = PasteoError.prototype;

module.exports = RuleViolationError;
