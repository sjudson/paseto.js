/***
 * JsonToken
 *
 * Paseto JSON token
 *
 * @constructor
 *
 * @api public
 *
 */
module.exports = JsonToken;
function JsonToken () {
	this.claims = {}
}


/***
 * get
 *
 * Get any arbitrary claim
 *
 * @function
 * @api public
 *
 * @param {String} name
 * @returns {mixed}
 */
JsonToken.prototype.get = function (claim) {
	if (claim in this.claims) {
		return this.claims[claim]
	}
	throw 'Claim not found'
}

/***
 * setClaims
 *
 * Set an object of claims in one go
 *
 * @function
 * @api public
 *
 * @param {Object} claims
 * @returns {JsonToken}
 */
JsonToken.prototype.setClaims = function (claims) {
	this.claims = {...claims, ...this.claims};
	return this
}

/***
 * getClaims
 *
 * Get all of the claims stored in this Paseto.
 *
 * @function
 * @api public
 *
 * @returns {Object}
 */
JsonToken.prototype.getClaims = function () {
	return this.claims
}