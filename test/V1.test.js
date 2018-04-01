const assert = require('assert');
const sodium = require('libsodium-wrappers');

describe('Protocol V1', () => {

  const _V1 = require('../lib/paseto').protocol.v1;
  const V1  = new _V1();

  describe('keygen', () => {

    const symmetric = _V1.generateSymmetricKey();

    assert.ok(symmetric instanceof require('../lib/key/symmetric'));

    assert.equal(V1.getSymmetricKeyByteLength(), Buffer.byteLength(symmetric.raw()));

  });

  describe('authenticated encryption', () => {

    let key, message, footer;;

    before(() => {
      const SymmetricKeyV1 = require('../lib/key/symmetric').V1;

      const rkey = Buffer.from(sodium.randombytes_buf(32));
      key = new SymmetricKeyV1(rkey);

      footer = 'footer';
    });

    describe('text', () => {

      before(() => {
        message = 'test';
      });

      it('should encrypt and decrypt successfully - callback api', (done) => {

        V1.encrypt(message, key, '', (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 9), 'v1.local.');

          V1.decrypt(token, key, '', (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should encrypt and decrypt successfully - promise api', (done) => {

        V1.encrypt(message, key, '')
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 9), 'v1.local.');

            return V1.decrypt(token, key, '');
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

        V1.encrypt(message, key, footer, (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 9), 'v1.local.');

          V1.decrypt(token, key, footer, (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should encrypt and decrypt successfully with footer - promise api', (done) => {

        V1.encrypt(message, key, footer)
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 9), 'v1.local.');

            return V1.decrypt(token, key, footer);
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

        V1.encrypt(message, key, '', (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 9), 'v1.local.');

          V1.decrypt(token, key, '', (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should encrypt and decrypt successfully - promise api', (done) => {

        V1.encrypt(message, key, '')
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 9), 'v1.local.');

            return V1.decrypt(token, key, '');
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

        V1.encrypt(message, key, footer, (err, token) => {
          if (err) { return done(err); }

          assert.equal(typeof token, 'string');
          assert.equal(token.substring(0, 9), 'v1.local.');

          V1.decrypt(token, key, footer, (err, data) => {
            if (err) { return done(err); }

            assert.equal(typeof data, 'string');
            assert.equal(data, message);

            done();
          });
        });
      });

      it('should encrypt and decrypt successfully with footer - promise api', (done) => {

        V1.encrypt(message, key, footer)
          .then((token) => {

            assert.equal(typeof token, 'string');
            assert.equal(token.substring(0, 9), 'v1.local.');

            return V1.decrypt(token, key, footer);
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

      const _V2 = require('../lib/protocol/V2');
      const V2  = new _V2();

      it('should error on encryption with an invalid key version - callback api', (done) => {

        V2.encrypt('test', key, '', function(err, token) {
          assert.ok(err);
          assert.ok(!token);

          assert.ok(err instanceof InvalidVersionError);
          assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

          done();
        });
      });

      it('should error on encryption with an invalid key version - promise api', (done) => {

        V2.encrypt('test', key, '')
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

        V1.encrypt('test', key, '', function(err, token) {
          if (err) { return done(err); }
          assert.ok(token);

          V2.decrypt(token, key, '', function(err, token) {
            assert.ok(err);
            assert.ok(!token);

            assert.ok(err instanceof InvalidVersionError);
            assert.equal(err.message, 'The given key is not intended for this version of PASETO.');

            done();
          });
        });
      });

      it('should error on decryption with an invalid key version - promise api', (done) => {

        V1.encrypt('test', key, '')
          .then((token) => {
            assert.ok(token);

            // nest so that we catch the right error
            return V2.decrypt(token, key, '')
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
