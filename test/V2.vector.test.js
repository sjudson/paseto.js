const assert = require('assert');


describe('Protocol V2 Test Vectors', () => {

  const _V2 = require('../lib/protocol/V2');
  const V2  = new _V2();

  describe('#2E - authenticated encryption', () => {

    let symmetricKey, nullKey, fullKey;

    before(() => {
      const SymmetricKeyV2 = require('../lib/key/symmetric').V2;

      const skey   = Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex');
      symmetricKey = new SymmetricKeyV2(skey);

      const nkey = Buffer.alloc(32).fill(0);
      nullKey    = new SymmetricKeyV2(nkey);

      const fkey = Buffer.alloc(32).fill(255, 0, 32);
      fullKey    = new SymmetricKeyV2(fkey);
    });

    describe('#1', () => {

      const nonce = Buffer.alloc(24).fill(0);

      it('#1 - Test Vector 2E-1-1 - callback', (done) => {
        V2.encrypt('', nullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ');
          done();
        });
      });

      it('#1 - Test Vector 2E-1-1 - promise', (done) => {
        V2.encrypt('', nullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });
  });
});
