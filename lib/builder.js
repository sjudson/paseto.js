const V1 = require('./protocol/V1');
const V2 = require('./protocol/V2');
const SymmetricKey = require('./key/symmetric');
const JsonToken = require('./jsontoken.js');

const allowedPurposes = ['local', 'public'];

/***
 * Builder
 *
 * Paseto key builder
 *
 * @constructor
 * @api public
 *
 * @param {JsonToken} baseToken
 * @param {V1|V2} protocol
 * @param {SymmetricKey} key
 */
module.exports = Builder;
function Builder(baseToken = null, protocol = null, key = null) {
	if (!protocol) {
		protocol = new V2();
	}
	if (!baseToken) {
		baseToken = new JsonToken();
	}
	this.token = baseToken;
	this.version = protocol;
	if (key) {
		this.setKey(key);
	}
}

/***
 * setKey
 *
 * Set the cryptographic key used to authenticate (and possibly encrypt)
 *
 * @function
 * @api public
 *
 * @param {SymmetricKey} key
 * @returns {Builder}
 */
Builder.prototype.setKey = function (key) {
	this.key = key;
	return this;
};

/**
 * set
 *
 * Set a claim to an arbitrary value
 * 
 * @param {String} claim
 * @param {String} value
 * @returns {Builder}
 */
Builder.prototype.set = function (claim, value) {
	this.token.set(claim, value);
	return this;
};

/**
 * setClaims
 *
 * Return a new Builder instance with an object of changed claims.
 *
 * @function
 * @api public
 *
 * @param {Object} claims
 * @returns {Builder}
 */
Builder.prototype.setClaims = function (claims) {
	this.token.setClaims(claims);
	return this;
};

/**
 * setExpiration
 *
 * Set the 'exp' claim for the token we're building.
 * 
 * @param {Date} time
 * @returns {Builder}
 */
Builder.prototype.setExpiration  = function (time = null) {
	this.token.setExpiration(time);
	return this;
};

/**
 * setIssuer
 *
 * Set the 'iss' claim for the token we're building. (Mutable.)
 * 
 * @param {String} iss
 * @returns {Builder}
 */
Builder.prototype.setIssuer = function (iss) {
    this.token.setIssuer(iss);
    return this;
};

/***
 * toString
 *
 * Get the token as a strinng
 *
 * @function
 * @api public
 *
 * @returns {String}
 */
Builder.prototype.toString = async function () {
	if (!this.key) {
		throw new Error('Key cannot be null')
	}
	if (!this.purpose) {
		throw new Error('Purpose cannot be null')
	}
	switch (this.purpose) {
		case 'local':
			return await this.version.encrypt(JSON.stringify(this.token.getClaims()), this.key, this.token.getFooter());
		case 'public':
			return await this.version.sign(JSON.stringify(this.token.getClaims()), this.key, this.token.getFooter());
		default:
			throw new Error('Purpose is not recognized');
	}
};

/**
 * setFooter
 *
 * Set the footer.
 *
 * @param {String} footer
 * @returns {Builder}
 */
Builder.prototype.setFooter = function (footer) {
	this.token.setFooter(footer);
	return this;
};

/**
 * setPurpose
 *
 * Set the purpose for this token
 *
 * @param {String} purpose
 * @returns {Builder}
 */
Builder.prototype.setPurpose = function (purpose) {
	if (!allowedPurposes.includes(purpose)) {
		throw new Error('Invalid purpose');
	}
	this.purpose = purpose;
	return this;
};
