# paseto.js

PASETO (aka Platform Agnostic SEcurity TOken) is an alternative to JWT, SAML, and any other cryptographically verified serialization format. It is a natural, drop-in replacement, well-suited for the same use cases - e.g., as bearer tokens in an authorization and/or authentication scheme - except significantly simpler and easier to use securely. For more information, there's an [overview](https://paragonie.com/blog/2018/03/paseto-platform-agnostic-security-tokens-is-secure-alternative-jose-standards-jwt-etc), a [website](https://paseto.io/) and [draft RFC](https://paseto.io/rfc/), and the documentation in the PHP [reference implementation](https://github.com/paragonie/paseto).

This repository holds `paseto.js`, an implementation of PASETO for Javascript, primarily the Node.js runtime but browser support is intended as well.

## Node.js

Ultimately, `paseto.js` will support two different APIs. To install, run

```bash
$ npm install paseto.js
```

or

```bash
$ yarn add paseto.js
```

#### High Level API

The high level API has not yet been implemented, and its completion will be an important step towards a first major release. It will have similar form to the [equivalent methods in the reference implementation](https://github.com/paragonie/paseto/tree/master/docs/02-PHP-Library#building-and-verifying-pasetos), allowing for very simple encoding and securing of a JSON object suitable e.g. for use in OpenID Connect.

#### Low Level API

The low level API is what is currently implemented, and allows for direct construction and manipulation of PASETOs. It requires constructing two core objects, an instantiation of a specific version of the protocol (presently `V1` or `V2`) and a suitable key.

```js
const Paseto = require('paseto.js');

const encoder = new Paseto.V2();
encoder.symmetric()
  .then(sk => {
    // (sk instanceof Paseto.SymmetricKey) -> true
    const message = 'A screaming comes across the sky.'

    return encoder.encrypt(message, sk);
  })
  .then(token => {
    console.log(token);
    // v2.local.kBENRnsihCbu2p2th-ilYwA8Sr9xj4YVcdc1Qftzmi4sFn0r5aGsq0ptcwuKldLzqzqziRUtC0Llc8vP28mq6aRxKtJKJZB9Lw
  });
```

##### Key Generation and Injection

Creation of key and protocol objects can be driven through either, provided you want `paseto.js` to generate the cryptographic keys for you.

```js
// first pattern
const sk = new Paseto.SymmetricKey(new Paseto.V1()); // if protocol is omitted, defaults to `new Paseto.V2()`
sk.generate()
  .then(() => {
    const encoder = sk.protocol();
    return encoder.encrypt(message, sk);
  });

// first pattern alt
const encoder = new Paseto.V1();
const sk      = new Paseto.SymmetricKey(encoder);
sk.generate().then(() => { return encoder.encrypt(message, sk); });

// second pattern
const encoder = new Paseto.V2();
encoder.symmetric().then(sk => { return encoder.encrypt(message, sk); });
```

You may also provide the keying material youself, but doing so requires using the first pattern.

```js
// raw
const raw = Buffer.from('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hex');
const sk  = new Paseto.SymmetricKey(new Paseto.V2());
sk.inject(raw)
  .then(() => {
    const encoder = sk.protocol();
    return encoder.encrypt(message, sk);
  });

// hex
const hex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const sk  = new Paseto.PrivateKey(new Paseto.V2());
sk.hex(hex)
  .then(() => {
    const encoder = sk.protocol();
    return encoder.encrypt(message, sk);
  });

// base64 (url safe)
const b64 = '2bqVCdL46MS4BbL40euZLqwILMaA6DFu6hciLvNaKfc';
const sk  = new Paseto.PublicKey(new Paseto.V2());
sk.base64(b64)
  .then(() => {
    const encoder = sk.protocol();
    return encoder.encrypt(message, sk);
  });
```

When in doubt, invoking the `inject` method with a raw `Buffer` is always the safest way to make sure `paseto.js` employs the key properly.

##### Key Extraction

To extract raw keying material for storage, you may use either the `encode` or `raw` methods on key objects. The former returns the key material encoded in Base64 (url safe), the latter returns a `Buffer` with raw bytes.

```js
const b64sk = sk.encode();
```

The `inject` and associated methods discussed above then allow this keying material to be used for future token processing.

Secure handling and storage of keying material is outside the scope of the library.

##### Message Encoding

Pursuant to the PASETO spec, all messages and footers must be `utf-8` encoded. It is recommended that binary data be encoded into Base64 (url safe) format to meet this requirement.

##### V1 or V2

At present PASETO specifies two variants, `V1` and `V2`. Choosing between these is simple - always pick `V2`. The specification of `V1` is intended for when you do not have a choice, and legacy or non-technical considerations force the use of older, less efficient and secure cryptographic constructions. Whenever possible, it is _strongly recommended_ that `V2` is used. For more, see [here](https://github.com/paragonie/paseto/tree/master/docs/01-Protocol-Versions).

##### Local

Local PASETOs are secured using an authenticated encryption scheme, either - if `V2` - XChaCha20-Poly1305 - or if `V1` - AES-256-CTR with HMAC-SHA384. They are accessible using the `encrypt` and `decrypt` methods for sending and receiving respectively.

```js
const encoder = new Paseto.V1();
const decoder = encoder;

let key;
encoder.symmetric()
  .then(sk => {
    key = sk;
    const message = 'A screaming comes across the sky.'

    return encoder.encrypt(message, sk);
  })
  .then(token => {
    console.log(token);
    // v1.local.cFb_8eCgll9NN6E5I8dd8vcStSqV0-G2zyROJa1fCe5TWl3J8_04TyFVIfB8R2Ljt6DqxHV99WycrSqZZ0lmuLf0fOwYE_Ien_P5BNwrm9P5elrtuP3GScgru2Mp1iMrHoGqwBjptYGhrJ0jH3vJBdQ

    return decoder.decrypt(token, key);
  })
  .then(message => {
    console.log(message);
    // A screaming comes across the sky.
  });
```

##### Public

Public PASETOs are secured using a signature scheme, meaning _they are not encrypted, only authenticated_. The scheme used is either - if `V2` - ed25519 - or if `V1` - RSASSA-PSS over SHA-384. They are accessible using the `sign` and `verify` methods for sending and receiving respectively. If using `V1`, the provided keys must be PEM encoded.

```js
const signer   = new Paseto.V2();
const verifier = signer;

let key, tok;
signer.private()
  .then(sk => {
    key = sk;
    const message = 'A screaming comes across the sky.'

    return signer.sign(message, sk);
  })
  .then(token => {
    tok = token;
    console.log(token);
    // v2.public.QSBzY3JlYW1pbmcgY29tZXMgYWNyb3NzIHRoZSBza3kusc8m2sPmtNSMuisjoNurB8WjPGd3bK_yn_z61_MKEX4dQjGp1qZf4Coci8iTfSEAl2chhZF3NbZ6siqjNOMuBQ

    return key.public();
  })
  .then(pub => { return verifier.verify(tok, pub); })
  .then(message => {
    console.log(message);
    // A screaming comes across the sky.
  });
```

##### Footers

The library includes support for footers, which are provided as a third argument to the `encrypt`, `decrypt`, `sign`, and `verify` methods. _NB: Before using footers it is highly recommended that you read the RFC, which contains pertinent information on their security_.

```js
const encoder = new Paseto.V2();
const decoder = encoder;

let key, footer = 'some other info';
encoder.symmetric()
  .then(sk => {
    key = sk;
    const message = 'A screaming comes across the sky.'

    return encoder.encrypt(message, sk, footer);
  })
  .then(token => {
    console.log(token);
    // v2.local.kBENRnsihCbu2p2th-ilYwA8Sr9xj4YVEfBOBKXEtB-_r0UUEOI87sal0D_CnzqkD5uAUZMdKL8gy3XAM5uo1O5Ih3x3oPkicg.c29tZSBvdGhlciBpbmZv

    return decoder.decrypt(token, key, footer);
  })
  .then(message => {
    console.log(message);
    // A screaming comes across the sky.
  });
```

##### Callbacks, Promises, and Async/Await

You may use any of callbacks, promises, or async/await with `paseto.js`. The only special consideration is that with the first approach, footers must explicitly be set to `null` if not provided.

```js
// callback
encoder.encrypt(message, sk, null, (err, token) => {
  if (err) { return cb(err); }
  console.log(token);
  // v2.local.kBENRnsihCbu2p2th-ilYwA8Sr9xj4YV4-l4mNKfi_hx9n0WfUYGGCjGkc2uRRuhpiVJXwcqedYtCn3Jo3pFRVe5DeNtN4IJxA
});

// promise
encoder.encrypt(message, sk).then(token => {
    console.log(token);
    // v2.local.kBENRnsihCbu2p2th-ilYwA8Sr9xj4YV4-l4mNKfi_hx9n0WfUYGGCjGkc2uRRuhpiVJXwcqedYtCn3Jo3pFRVe5DeNtN4IJxA
  });

// async/await (more extensive example)
(async () => {
  const encoder = new Paseto.V2();
  const message = 'A screaming comes across the sky.';

  const sk    = await encoder.symmetric();
  const token = await encoder.encrypt(message, sk);
  console.log(token);
  // v2.local.kBENRnsihCbu2p2th-ilYwA8Sr9xj4YV4-l4mNKfi_hx9n0WfUYGGCjGkc2uRRuhpiVJXwcqedYtCn3Jo3pFRVe5DeNtN4IJxA
})();
```

## Browser

Limited browser support (solely for verification of public tokens) is intended for the first major release.

## Incidentals

This library was written and is maintained by [Samuel Judson](https://github.com/sjudson). It is published under the MIT License. Pull requests and issues are welcome, however the intent is to maintain parity with the reference implementation, so non-specification feature requests will be redirected there.