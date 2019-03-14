class JsonToken {

  constructor () {
    this.claims = {}
  }
  
  /**
   * Get any arbitrary claim
   * @param  {String} claim
   * @return {[mixed]}
   */
  get (claim) {
    if (claim in this.claims) {
      return this.claims[claim]
    }
    throw 'Claim not found'
  }

  /**
   * Set an object of claims in one go
   * @param {Object} claims
   */
  setClaims (claims) {
    this.claims = {...claims, ...this.claims};
    return this
  }

  /**
   * Get all of the claims stored in this Paseto.
   * @return {Object}
   */
  getClaims() {
    return this.claims
  }
}

module.exports = JsonToken;
