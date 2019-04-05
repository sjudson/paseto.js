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
	this.claims = {};
	this.footer = '';
}


/***
 * get
 *
 * Get any arbitrary claim
 *
 * @function
 * @api public
 *
 * @param {String} claim
 * @returns {*}
 */
JsonToken.prototype.get = function get(claim) {
	if (claim in this.claims) {
		return this.claims[claim];
	}
	throw new Error('Claim not found');
};

/**
 * set
 *
 * Set a claim to an arbitrary value.
 * 
 * @param {String} claim 
 * @param {String} value
 *
 * @returns {JsonToken}
 */
JsonToken.prototype.set = function set(claim, value) {
	this.claims[claim] = value;
	return this;
};

/**
 * setExpiration
 *
 * Set the 'exp' claim.
 * 
 * @param {Date} time
 * @returns {JsonToken}
 */
JsonToken.prototype.setExpiration = function setExpiration(time = null) {
	if (!time) {
		time = new Date();
	}
	this.claims['exp'] = time.toISOString();
	return this;
};

/**
 * setIssuer
 *
 * Set the 'iss' claim
 * 
 * @param {String} iss
 * @returns {JsonToken}
 */
JsonToken.prototype.setIssuer = function setIssuer(iss) {
    this.claims['iss'] = iss;
    return this;
};

/**
 * getExpiration
 *
 * Get the 'exp' claim.
 * @return {Date}
 */
JsonToken.prototype.getExpiration = function getExpiration() {
	return new Date(this.claims['exp']);
};

/**
 * getIssuer
 *
 * Get the 'iss' claim
 * @return {String}
 */
JsonToken.prototype.getIssuer = function getIssuer() {
    return this.claims['iss'];
};

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
	return this;
};

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
	return this.claims;
};

/**
 * getFooter
 *
 * Get the footer as a string.
 *
 * @returns {String}
 */
JsonToken.prototype.getFooter = function () {
	return this.footer;
};

/**
 * setFooter
 *
 * Set the footer
 *
 * @param {String} footer
 * @returns {JsonToken}
 */
JsonToken.prototype.setFooter = function (footer) {
	this.footer = footer;
	return this;
};
