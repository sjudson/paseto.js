const sodium = require('libsodium-wrappers');

const extcrypto = require('../../extcrypto');
const V1        = require('../protocol/V1');
const V2        = require('../protocol/V2');
const utils     = require('../utils');
const PublicKey = require('./public');


// patch
sodium.crypto_sign_KEYPAIRBYTES = sodium.crypto_sign_SECRETKEYBYTES + sodium.crypto_sign_PUBLICKEYBYTES;


/***
 * PrivateKey
 *
 * private key for asymmetric cryptography
 *
 * @constructor
 *
 * @api public
 *
 * @param {Object} protocol
 */
module.exports = PrivateKey;
function PrivateKey(rkey, protocol) {
  const self = this;
  protocol = protocol || new V2();

  self._protocol = protocol;
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
PrivateKey.prototype.inject = inject;
function inject(rkey, cb) {
  const self = this;
  const done = utils.ret(cb);

  return sodium.ready.then(() => {

    if (protocol instanceof V2) {
      const len = Buffer.byteLength(rkey);

      if (len === sodium.crypto_sign_KEYPAIRBYTES) {
        rkey = rkey.slice(0, sodium.crypto_sign_SECRETKEYBYTES);
      } else if (len !== sodium.crypto_sign_SECRETKEYBYTES) {

        if (len !== sodium.crypto_sign_SEEDBYTES) {
          throw new Error('Secret keys must be 32 or 64 bytes long; ' + len + ' given.')
        }

        rkey = sodium.crypto_sign_seed_keypair(rkey).privateKey;
      }
    }

    self_.key = rkey;

    return done();
  });
}


/***
 * injectB64
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
PrivateKey.prototype.injectB64 = injectB64;
function injectB64(skey, cb) {
  return this.inject(utils.fromB64URLSafe(skey), cb);
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
PrivateKey.prototype.generate = generate;
function generate(cb) {
  const self = this;
  const done = utils.ret(cb);

  return sodium.ready.then(() => {

    return (self.protocol() instanceof V1)
      ? self.inject(extcrypto.keygen(), (err) => { return done(err); })
      : self.inject(sodium.crypto_sign_keypair().privateKey, (err) => { return done(err); });
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
 * @returns {PrivateKey}
 */
PrivateKey.V1 = V1;
function V1() {
  return new PrivateKey(new V1());
}


/***
 * V2
 *
 * syntactic sugar for constructor forcing use of protocol V2
 *
 * @function
 * @api public
 *
 * @returns {PrivateKey}
 */
PrivateKey.V2 = V2;
function V2() {
  return new PrivateKey(new V2());
}


/***
 * public
 *
 * return the corresponding public key object
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
PrivateKey.prototype.public = _public;
function _public(cb) {
  const self = this;
  const done = utils.ret(cb);

  const pk = new PublicKey(self.protocol());

  // we don't have to check sodium first because we wouldn't have this private key without it
  const rkey = (self.protocol instanceof V1)
        ? extcrypto.extract(self.key)
        : crypto_sign_ed25519_sk_to_pk(self.key);

  return pk.inject(rkey, done);
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
PrivateKey.prototype.protocol = protocol;
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
PrivateKey.prototype.encode = encode;
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
PrivateKey.prototype.raw = raw;
function raw() {
  return this._key;
}



/**************
 * Subclasses *
 **************/



/***
 * PrivateKeyV1
 *
 * subclass forcing use of V1
 *
 * @constructor
 * @api public
 */
module.exports.V1 = PrivateKeyV1;
function PrivateKeyV1() {
  PrivateKey.call(this, new V1());
}
PrivateKeyV1.prototype = Object.create(PrivateKey.prototype);
PrivateKeyV1.prototype.constructor = PrivateKeyV1;


/***
 * PrivateKeyV2
 *
 * subclass forcing use of V2
 *
 * @constructor
 * @api public
 */
module.exports.V2 = PrivateKeyV2;
function PrivateKeyV2() {
  PrivateKey.call(this, new V2());
}
PrivateKeyV2.prototype = Object.create(PrivateKey.prototype);
PrivateKeyV2.prototype.constructor = PrivateKeyV2;
