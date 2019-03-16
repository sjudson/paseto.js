const V1 = require('./protocol/V1')
const V2 = require('./protocol/V2')
const SymmetricKey = require('./key/symmetric')
const JsonToken = require('./jsontoken.js')

const protocols = {
  v1: V1,
  v2: V2
}

class Parser {
  constructor (key = null) {
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
   * Parse a string into a JSON Object
   * @param  {String} token 
   * @return {Object}}
   */
  async parse (token) {
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
}

module.exports = Parser
