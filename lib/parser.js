const V1 = require('./protocol/V1')
const V2 = require('./protocol/V2')
const SymmetricKey = require('./key/symmetric')
const JsonToken = require('./jsontoken.js')

const protocols = {
	v1: V1,
	v2: V2
}

/***
 * Parser
 *
 * Paseto key parser
 *
 * @constructor
 *
 * @api public
 *
 */
module.exports = Parser;
function Parser (key = null) {
	if (key) {
		this.setKey(key);
	}
}

/***
 * setKey
 *
 * Specify the key for the token we are going to parse.
 * 
 * @function
 * @api public
 *
 * @param {SymmetricKey} key
 * @returns {Parser}
 */
Parser.prototype.setKey = function (key) {
	this.key = key;
	return this;
}

/***
 * parse
 *
 * Parse a string into a JSON Object
 *
 * @function
 * @api public
 *
 * @param {String} token
 * @returns {Object}
 */
Parser.prototype.parse = async function (token ) {
	const pieces = token.split('.')
	if (pieces.length < 3) {
		throw 'Truncated or invalid token'
	}
	const header = {
		version: pieces[0],
		purpose: pieces[1]
	}
	const protocol = new protocols[header.version]()

	switch(header.purpose) {
		case 'local':
		return JSON.parse(await protocol.decrypt(token, this.key));
		break;
	}
}