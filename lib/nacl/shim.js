if (process.env.NODE_ENV && process.env.NODE_ENV == 'development') {

  const nacl   = require('tweetnacl');
  const base64 = require('@stablelib/base64');
  
  exports = module.exports = {
    ready:       () => { return new Promise((resolve, reject) => { return resolve(); }) },
    // if verify == true then (1 & !true) == 0, if verify == false then (1 & !false) == 1 -- nb: we don't care how they are unequal, just that they are unequal
    compare: (a, b) => { let g = 1; return g & !nacl.verify(a, b) }, // 

    base64_variants: { URLSAFE_NO_PADDING: true },
    to_base64: (bytes, _) => { return base64.encodeURLSafe(bytes); },
    from_base64: (str, _) => { return base64.decodeURLSafe(str); },

    crypto_sign_BYTES: nacl.sign.signatureLength,
    crypto_sign_PUBLICKEYBYTES: nacl.sign.publicKeyLength,
    crypto_sign_verify_detached: (s, m, k) => { return nacl.sign.detached.verify(m, s, k); }
  }

} else {
  exports = module.exports = require('libsodium-wrappers-sumo');
}
