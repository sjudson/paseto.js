const rule = require('./rule');

module.exports = NotExpired;

NotExpired.prototype = new rule();
function NotExpired (now) {
	if (!now) {
		now = new Date();
	}
	this.now = now;
}

NotExpired.prototype.isValid = function (token) {
	const expires = token.getExpiration();
	if (expires < this.now) {
		this.failure = 'This token has expired';
		return false;
	}
	return true;
}