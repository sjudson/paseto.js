const assert = require('assert');
const sodium = require('libsodium-wrappers');

describe('Protocol V2', () => {

  const _V2 = require('../lib/protocol/V2');
  const V2  = new _V2();

  describe('authenticated encryption', () => {

    let key, message, footer;;

    before(() => {
      const SymmetricKeyV2 = require('../lib/key/symmetric').V2;

      const rkey = Buffer.from(sodium.randombytes_buf(32));
      key = new SymmetricKeyV2(rkey);

      footer = 'footer';
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

    // to add when V1 is finished
    it.skip('should error on encryption with an invalid key version - callback api', (done) => {});
    it.skip('should error on encryption with an invalid key version - promise api', (done) => {});
    it.skip('should error on decryption with an invalid key version - callback api', (done) => {});
    it.skip('should error on decryption with an invalid key version - promise api', (done) => {});
  });
});
