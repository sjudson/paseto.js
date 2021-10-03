const rule = require('./rule');

module.exports = IssuedBy;

IssuedBy.prototype = new rule();
function IssuedBy (issuer) {
  this.issuer = issuer
}

IssuedBy.prototype.isValid = function (token) {
  const issuedBy = token.getIssuer();
  if (issuedBy !== this.issuer) {
    this.failure = `This token was not issued by ${this.issuer} (expected); it was issued by ${issuedBy} instead.`;
    return false;
  }
  return true;
}