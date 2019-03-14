const V1 = require('./protocol/V1')
const V2 = require('./protocol/V2')
const SymmetricKey = require('./key/symmetric')
const JsonToken = require('./jsontoken.js')

class Builder {
  constructor(baseToken = null, protocol = null, key = null) {
    if (!protocol) {
      protocol = new V2();
    }
    if (!baseToken) {
      baseToken = new JsonToken()
    }
    this.token = baseToken;
    this.version = protocol;
    if (key) {
      this.setKey(key)
    }
  }

  /**
   * Set the cryptographic key used to authenticate (and possibly encrypt)
   * @param {SymmetricKey} key
   */
  setKey(key) {
    this.key = key
    return this
  }

  /**
   * Return a new Builder instance with an object of changed claims.
   * @param {Object} claims
   * @return self
   */
  setClaims(claims) {
    this.token.setClaims(claims)
    return this
  }

  /**
   * Get the token as a strinng
   * @return {String} [description]
   */
  toString () {
    if (!this.key) {
      throw 'Key cannot be null'
    }
    return this.version.encrypt(JSON.stringify(this.token.getClaims()), this.key)
      .then(token => {
        return token
      })
  }
}

module.exports = Builder;
