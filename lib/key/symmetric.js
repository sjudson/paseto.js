const sodium = require('libsodium-wrappers-sumo');
const crypto = require('crypto');

const V1    = require('../protocol/V1');
const V2    = require('../protocol/V2');
const utils = require('../utils');


/***
 * SymmetricKey
 *
 * secret key for symmetric cryptography
 *
 * @constructor
 *
 * @api public
 *
 * @param {Object} protocol
 */
module.exports = SymmetricKey;
function SymmetricKey(protocol) {
  const self = this;

  self.INFO_ENCRYPTION     = 'paseto-encryption-key';
  self.INFO_AUTHENTICATION = 'paseto-auth-key-for-aead';

  self._protocol = protocol || new V2();
}


/***
 * inject
 *
 * complete construction asynchronously
 *
 * @function
 *
 * @api public
 *
 * @param {Buffer} rkey
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
SymmetricKey.prototype.inject = inject;
function inject(rkey, cb) {
  const self = this;
  const done = utils.ret(cb);

  if (!(rkey instanceof Buffer)) { return done(new TypeError('Raw key must be provided as a buffer')); }

  return sodium.ready.then(() => {
    self._key = rkey;
    return done();
  });
}


/***
 * base64
 *
 * complete construction asynchronously using base64 encoded key
 *
 * @function
 *
 * @api public
 *
 * @param {Buffer} skey
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
SymmetricKey.prototype.base64 = base64;
function base64(skey, cb) {
  return this.inject(utils.fromB64URLSafe(skey), cb);
}


/***
 * hex
 *
 * complete construction asynchronously using hex encoded key
 *
 * @function
 *
 * @api public
 *
 * @param {Buffer} skey
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
SymmetricKey.prototype.hex = hex;
function hex(skey, cb) {
  return this.inject(Buffer.from(skey, 'hex'), cb);
}


/***
 * generate
 *
 * complete construction asynchronously, generating key
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
SymmetricKey.prototype.generate = generate;
function generate(cb) {
  const self = this;
  const done = utils.ret(cb);

  return sodium.ready.then(() => {
    return self.inject(crypto.randomBytes(self.protocol().sklength()), (err) => { return done(err); });
  });
}


/***
 * V1
 *
 * syntactic sugar for constructor forcing use of protocol V1
 *
 * @function
 * @api public
 *
 * @returns {SymmetricKey}
 */
SymmetricKey.V1 = v1;
function v1() {
  return new SymmetricKey(new V1());
}


/***
 * V2
 *
 * syntactic sugar for constructor forcing use of protocol V2
 *
 * @function
 * @api public
 *
 * @returns {SymmetricKey}
 */
SymmetricKey.V2 = v2;
function v2() {
  return new SymmetricKey(new V2());
}


/***
 * protocol
 *
 * return the underlying protocol object
 *
 * @function
 * @api public
 *
 * @returns {Object}
 */
SymmetricKey.prototype.protocol = protocol;
function protocol() {
  return this._protocol;
}


/***
 * encode
 *
 * encode the raw key as b64url
 *
 * @function
 * @api public
 *
 * @returns {String}
 */
SymmetricKey.prototype.encode = encode;
function encode() {
  return utils.toB64URLSafe(this._key);
}


/***
 * raw
 *
 * return the raw key buffer
 *
 * @function
 * @api public
 *
 * @returns {Buffer}
 */
SymmetricKey.prototype.raw = raw;
function raw() {
  return this._key;
}


/***
 * split
 *
 * split into subkeys
 *
 * @function
 * @api private
 *
 * @param {Buffer} salt
 * @param {Function} done
 * @returns {Array}
 */
SymmetricKey.prototype.split = split;
function split(salt, done) {
  const self = this;
  const hkdf = utils.hkdf('sha384');

  hkdf(self._key, salt, 32, self.INFO_ENCRYPTION, (err, ekey) => {
    if (err) { return done(err); }

    hkdf(self._key, salt, 32, self.INFO_AUTHENTICATION, (err, akey) => {
      if (err) { return done(err); }
      return done(null, [ ekey, akey ]);
    });
  });
}



/**************
 * Subclasses *
 **************/



/***
 * SymmetricKeyV1
 *
 * subclass forcing use of V1
 *
 * @constructor
 * @api public
 */
module.exports.V1 = SymmetricKeyV1;
function SymmetricKeyV1() {
  SymmetricKey.call(this, new V1());
}
SymmetricKeyV1.prototype = Object.create(SymmetricKey.prototype);
SymmetricKeyV1.prototype.constructor = SymmetricKeyV1;


/***
 * SymmetricKeyV2
 *
 * subclass forcing use of V2
 *
 * @constructor
 * @api public
 */
module.exports.V2 = SymmetricKeyV2;
function SymmetricKeyV2() {
  SymmetricKey.call(this, new V2());
}
SymmetricKeyV2.prototype = Object.create(SymmetricKey.prototype);
SymmetricKeyV2.prototype.constructor = SymmetricKeyV2;
