const V1 = require('./protocol/V1');
const V2 = require('./protocol/V2');
const SymmetricKey = require('./key/symmetric');
const JsonToken = require('./jsontoken.js');
const utils = require('./utils.js');
const Rule = require('./rules/rule');

const protocols = {
  v1: V1,
  v2: V2
};

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

function Parser(key = null) {
  if (key) {
    this.setKey(key);
  }
  this.rules = []
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
};

/**
 * addRule
 *
 * Add a validation rule to be invoked by parse().
 *
 * @param {Rule} rule
 */
Parser.prototype.addRule = function (rule) {
  this.rules.push(rule);
  return this;
};

/**
 * validate
 *
 * Does this token pass all of the rules defined?
 *
 * @param  {JsonToken} token
 * @return {Boolean}
 */
Parser.prototype.validate = function (token) {
  if (this.rules.length === 0) {
    return true
  }
  for (let rule of this.rules) {
    if (!(rule instanceof Rule)) {
      throw new Error('Invalid rule');
    }
    if (!rule.isValid(token)) {
      throw new Error(rule.failure);
    }
  }
  return true;
};

/***
 * parse
 *
 * Parse a string into a JSON Object
 *
 * @function
 * @api public
 *
 * @param {String} tainted
 * @returns {Object}
 */
Parser.prototype.parse = async function (tainted) {
  const pieces = tainted.split('.');
  if (pieces.length < 3) {
    throw 'Truncated or invalid token'
  }
  const header = {
    version: pieces[0],
    purpose: pieces[1]
  };
  const footer = pieces.length > 3 ? utils.fromB64URLSafe(pieces[3]).toString() : '';

  const protocol = new protocols[header.version]();

  let claims, token;
  switch (header.purpose) {
    case 'local':
      claims = JSON.parse(await protocol.decrypt(tainted, this.key, footer));
      token = new JsonToken().setFooter(footer).setClaims(claims);
      break;
    case 'public':
      claims = JSON.parse(await protocol.verify(tainted, this.key, footer));
      token = new JsonToken().setFooter(footer).setClaims(claims);
      break;
  }
  this.validate(token);
  return token;
};
