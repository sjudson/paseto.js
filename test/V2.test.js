const assert = require('assert');
const sodium = require('libsodium-wrappers-sumo');

const Paseto = require('../lib/paseto');

describe('Protocol V2', () => {

  const V2 = new Paseto.V2();

  describe('keygen', () => {

    it('should generate a symmetric key', (done) => {
      V2.symmetric((err, sk) => {
        if (err) { return done(err); }

        assert.ok(sk instanceof Paseto.SymmetricKey);
        assert.equal(V2.sklength(), Buffer.byteLength(sk.raw()));

        done();
      });
    });

    it('should generate a private key', (done) => {
      V2.private((err, pk) => {
        if (err) { return done(err); }

        assert.ok(pk instanceof Paseto.PrivateKey);
        assert.equal(64, Buffer.byteLength(pk.raw()));

        done();
      });
    });
  });

  describe('authenticated encryption', () => {

    let key, message, footer;

    before((done) => {
      footer = 'footer';

      const rkey = Buffer.from(sodium.randombytes_buf(32));

      key = new Paseto.SymmetricKey.V2();
      key.inject(rkey, done);
    });

    describe('text', () => {

      before(() => {
        message = 'test';
      });

      it('should encrypt and decrypt successfully - callback api', (done) => {

        V2.encrypt(message, key, '', (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 9), 'v2.local.');

          V2.decrypt(token, key, '', (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should encrypt and decrypt successfully - promise api', (done) => {

        V2.encrypt(message, key, '')
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 9), 'v2.local.');

            return V2.decrypt(token, key, '');
          })
          .then((data) => {

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            return done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('should encrypt and decrypt successfully with footer - callback api', (done) => {

        V2.encrypt(message, key, footer, (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 9), 'v2.local.');

          V2.decrypt(token, key, footer, (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should encrypt and decrypt successfully with footer - promise api', (done) => {

        V2.encrypt(message, key, footer)
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 9), 'v2.local.');

            return V2.decrypt(token, key, footer);
          })
          .then((data) => {

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            return done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('json (stringified)', () => {

      before(() => {
        const year = new Date().getUTCFullYear() + 1;
        message = JSON.stringify({ data: 'this is a signed message', expires: year + '-01-01T00:00:00+00:00' });
      });

      it('should encrypt and decrypt successfully - callback api', (done) => {

        V2.encrypt(message, key, '', (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 9), 'v2.local.');

          V2.decrypt(token, key, '', (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should encrypt and decrypt successfully - promise api', (done) => {

        V2.encrypt(message, key, '')
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 9), 'v2.local.');

            return V2.decrypt(token, key, '');
          })
          .then((data) => {

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            return done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('should encrypt and decrypt successfully with footer - callback api', (done) => {

        V2.encrypt(message, key, footer, (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 9), 'v2.local.');

          V2.decrypt(token, key, footer, (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should encrypt and decrypt successfully with footer - promise api', (done) => {

        V2.encrypt(message, key, footer)
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 9), 'v2.local.');

            return V2.decrypt(token, key, footer);
          })
          .then((data) => {

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            return done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('errors', () => {

      const InvalidVersionError = require('../lib/error/InvalidVersionError');

      const V1 = new Paseto.V1();

      it('should error on encryption with an invalid key version - callback api', (done) => {

        V1.encrypt('test', key, '', function(err, token) {
          assert.ok(err);
          assert.ok(!token);

          assert.ok(err instanceof InvalidVersionError);
          assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

          done();
        });
      });

      it('should error on encryption with an invalid key version - promise api', (done) => {

        V1.encrypt('test', key, '')
          .then((token) => {
            assert.ok(false); // fail if we go through here
          })
          .catch((err) => {
            assert.ok(err);

            assert.ok(err instanceof InvalidVersionError);
            assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

            done();
          });
      });

      it('should error on decryption with an invalid key version - callback api', (done) => {

        V2.encrypt('test', key, '', function(err, token) {
          if (err) { return done(err); }
          assert.ok(token);

          V1.decrypt(token, key, '', function(err, token) {
            assert.ok(err);
            assert.ok(!token);

            assert.ok(err instanceof InvalidVersionError);
            assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

            done();
          });
        });
      });

      it('should error on decryption with an invalid key version - promise api', (done) => {

        V2.encrypt('test', key, '')
          .then((token) => {
            assert.ok(token);

            // nest so that we catch the right error
            return V1.decrypt(token, key, '')
              .then((token) => {
                assert.ok(false); // fail if we go through here
              })
              .catch((err) => {
                assert.ok(err);

                assert.ok(err instanceof InvalidVersionError);
                assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

                done();
              });
          })
          .catch((err) => {
            return done(err);
          });
      });
    });
  });

  describe('signing', () => {

    let sk, pk, message, footer;

    before((done) => {
      footer = 'footer';

      const keypair = sodium.crypto_sign_keypair();

      sk = new Paseto.PrivateKey.V2();
      sk.inject(Buffer.from(keypair.privateKey, 'binary'), (err) => {
        if (err) { return done(err); }

        pk = new Paseto.PublicKey.V2();
        pk.inject(Buffer.from(keypair.publicKey, 'binary'), done);
      });
    });

    describe('text', () => {

      before(() => {
        message = 'test';
      });

      it('should sign and verify successfully - callback api', (done) => {

        V2.sign(message, sk, '', (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 10), 'v2.public.');

          V2.verify(token, pk, '', (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should sign and verify successfully - promise api', (done) => {

        V2.sign(message, sk, '')
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 10), 'v2.public.');

            return V2.verify(token, pk, '');
          })
          .then((data) => {

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            return done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('should sign and verify successfully with footer - callback api', (done) => {

        V2.sign(message, sk, footer, (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 10), 'v2.public.');

          V2.verify(token, pk, footer, (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should sign and verify successfully with footer - promise api', (done) => {

        V2.sign(message, sk, footer)
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 10), 'v2.public.');

            return V2.verify(token, pk, footer);
          })
          .then((data) => {

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            return done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('json (stringified)', () => {

      before(() => {
        const year = new Date().getUTCFullYear() + 1;
        message = JSON.stringify({ data: 'this is a signed message', expires: year + '-01-01T00:00:00+00:00' });
      });

      it('should sign and verify successfully - callback api', (done) => {

        V2.sign(message, sk, '', (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 10), 'v2.public.');

          V2.verify(token, pk, '', (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should sign and verify successfully - promise api', (done) => {

        V2.sign(message, sk, '')
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 10), 'v2.public.');

            return V2.verify(token, pk, '');
          })
          .then((data) => {

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            return done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('should sign and verify successfully with footer - callback api', (done) => {

        V2.sign(message, sk, footer, (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 10), 'v2.public.');

          V2.verify(token, pk, footer, (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should sign and verify successfully with footer - promise api', (done) => {

        V2.sign(message, sk, footer)
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 10), 'v2.public.');

            return V2.verify(token, pk, footer);
          })
          .then((data) => {

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            return done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('errors', () => {

      const InvalidVersionError = require('../lib/error/InvalidVersionError');

      const V1 = new Paseto.V1();

      it('should error on signing with an invalid key version - callback api', (done) => {

        V1.sign('test', sk, '', function(err, token) {
          assert.ok(err);
          assert.ok(!token);

          assert.ok(err instanceof InvalidVersionError);
          assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

          done();
        });
      });

      it('should error on signing with an invalid key version - promise api', (done) => {

        V1.sign('test', sk, '')
          .then((token) => {
            assert.ok(false); // fail if we go through here
          })
          .catch((err) => {
            assert.ok(err);

            assert.ok(err instanceof InvalidVersionError);
            assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

            done();
          });
      });

      it('should error on verifying with an invalid key version - callback api', (done) => {

        V2.sign('test', sk, '', function(err, token) {
          if (err) { return done(err); }
          assert.ok(token);

          V1.verify(token, pk, '', function(err, token) {
            assert.ok(err);
            assert.ok(!token);

            assert.ok(err instanceof InvalidVersionError);
            assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

            done();
          });
        });
      });

      it('should error on verifing with an invalid key version - promise api', (done) => {

        V2.sign('test', sk, '')
          .then((token) => {
            assert.ok(token);

            // nest so that we catch the right error
            return V1.verify(token, pk, '')
              .then((token) => {
                assert.ok(false); // fail if we go through here
              })
              .catch((err) => {
                assert.ok(err);

                assert.ok(err instanceof InvalidVersionError);
                assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

                done();
              });
          })
          .catch((err) => {
            return done(err);
          });
      });
    });
  });
});
