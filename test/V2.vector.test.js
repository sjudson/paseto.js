const assert = require('assert');

describe('Protocol V2 Test Vectors', () => {

  const _V2 = require('../lib/paseto').protocol.v2;
  const V2  = new _V2();

  describe('#2E - authenticated encryption', () => {

    // NOTE: Throughout these tests we use the undocumented __encrypt API, allowing us to
    //       provide custom nonce parameters, needed for aligning with known test vectors.

    let symmetricKey, nullKey, fullKey, nonce;

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

      before(() => {
        nonce = Buffer.alloc(24).fill(0);
      });

      it('#1 - Test Vector 2E-1-1 - callback api', (done) => {
        V2.__encrypt('', nullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ');
          done();
        });
      });

      it('#1 - Test Vector 2E-1-1 - promise api', (done) => {
        V2.__encrypt('', nullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 2E-1-2 - callback api', (done) => {
        V2.__encrypt('', fullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg');
          done();
        });
      });

      it('#2 - Test Vector 2E-1-2 - promise api', (done) => {
        V2.__encrypt('', fullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 2E-1-3 - callback api', (done) => {
        V2.__encrypt('', symmetricKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA');
          done();
        });
      });

      it('#3 - Test Vector 2E-1-3 - promise api', (done) => {
        V2.__encrypt('', symmetricKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('#2', () => {

      before(() => {
        nonce = Buffer.alloc(24).fill(0);
      });

      it('#1 - Test Vector 2E-2-1 - callback api', (done) => {
        V2.__encrypt('', nullKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#1 - Test Vector 2E-2-1 - promise api', (done) => {
        V2.__encrypt('', nullKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 2E-2-2 - callback api', (done) => {
        V2.__encrypt('', fullKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#2 - Test Vector 2E-2-2 - promise api', (done) => {
        V2.__encrypt('', fullKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 2E-2-3 - callback api', (done) => {
        V2.__encrypt('', symmetricKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#3 - Test Vector 2E-2-3 - promise api', (done) => {
        V2.__encrypt('', symmetricKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('#3', () => {

      before(() => {
        nonce = Buffer.alloc(24).fill(0);
      });

      it('#1 - Test Vector 2E-3-1 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', nullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0');
          done();
        });
      });

      it('#1 - Test Vector 2E-3-1 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', nullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 2E-3-2 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', fullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw');
          done();
        });
      });

      it('#2 - Test Vector 2E-3-2 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', fullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 2E-3-3 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', symmetricKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U');
          done();
        });
      });

      it('#3 - Test Vector 2E-3-3 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', symmetricKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('#4', () => {

      before(() => {
        nonce = Buffer.from('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b', 'hex');
      });

      it('#1 - Test Vector 2E-4-1 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', nullKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#1 - Test Vector 2E-4-1 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', nullKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 2E-4-2 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', fullKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#2 - Test Vector 2E-4-2 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', fullKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 2E-4-3 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', symmetricKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#3 - Test Vector 2E-4-3 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', symmetricKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('json test', () => {

      let message, footer;

      before(() => {
        nonce   = Buffer.from('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b', 'hex');
        message = JSON.stringify({ data: 'this is a signed message', expires: '2019-01-01T00:00:00+00:00' });
        footer  = 'Paragon Initiative Enterprises';
      });

      it('callback api', (done) => {
        V2.__encrypt(message, symmetricKey, footer, nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz');
          done();
        });
      });

      it('promise api', (done) => {
        V2.__encrypt(message, symmetricKey, footer, nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });
  });
});
