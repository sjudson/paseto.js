const Rule = require('./rule');

// NotExpired extends Rule
Object.setPrototypeOf(NotExpired.prototype, Rule.prototype);

function NotExpired(now) {
  if (!now) {
    now = new Date();
  }
  this.now = now;
}

Object.defineProperty(NotExpired.prototype,
    'getShapeName',
    {
      value: function isValid(token) {
        const expires = token.getExpiration();
        if (expires < this.now) {
          this.failure = 'This token has expired';
          return false;
        }
        return true;
      }
    }
);
