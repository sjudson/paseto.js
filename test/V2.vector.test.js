const assert = require('assert');

const Paseto = require('../lib/paseto');

describe('Protocol V2 Test Vectors', () => {

  const V2 = new Paseto.V2();

  describe('V2 Official Test Vectors', () => {

    // NOTE: Throughout these tests we use the undocumented __encrypt API, allowing us to
    //       provide custom nonce parameters, needed for aligning with known test vectors.

    let symmetricKey, nonce1, nonce2, privateKey, publicKey;

    before((done) => {
      const skey   = Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex');
      symmetricKey = new Paseto.SymmetricKey.V2();
      symmetricKey.inject(skey, (err) => {
        if (err) { return done(err); }

        nonce1 = Buffer.alloc(24).fill(0);;
        nonce2 = Buffer.from('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b', 'hex');

        const prkey = Buffer.from('b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2', 'hex');
        const pukey = Buffer.from('1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2', 'hex');
        privateKey = new Paseto.PrivateKey.V2();
        publicKey = new Paseto.PublicKey.V2();

        privateKey.inject(prkey, (err) => {
          if (err) { return done(err); }
          publicKey.inject(pukey, done);
        });
      });
    });

    it('Test Vector 2-E-1 - callback api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});

      V2.__encrypt(message, symmetricKey, '', nonce1, (err, token) => {
        if (err) { return done(err); }
        assert.equal(token, 'v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ');

        done();
      });
    });

    it('Test Vector 2-E-1 - promise api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});

      V2.__encrypt(message, symmetricKey, '', nonce1)
        .then((token) => {
          assert.equal(token, 'v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('Test Vector 2-E-2 - callback api', (done) => {
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00'});

      V2.__encrypt(message, symmetricKey, '', nonce1, (err, token) => {
        if (err) { return done(err); }
        assert.equal(token, 'v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w');

        done();
      });
    });

    it('Test Vector 2-E-2 - promise api', (done) => {
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00'});

      V2.__encrypt(message, symmetricKey, '', nonce1)
        .then((token) => {
          assert.equal(token, 'v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('Test Vector 2-E-3 - callback api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});

      V2.__encrypt(message, symmetricKey, '', nonce2, (err, token) => {
        if (err) { return done(err); }
        assert.equal(token, 'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA');

        done();
      });
    });

    it('Test Vector 2-E-3 - promise api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});

      V2.__encrypt(message, symmetricKey, '', nonce2)
        .then((token) => {
          assert.equal(token, 'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('Test Vector 2-E-4 - callback api', (done) => {
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00'});

      V2.__encrypt(message, symmetricKey, '', nonce2, (err, token) => {
        if (err) { return done(err); }
        assert.equal(token, 'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ');

        done();
      });
    });

    it('Test Vector 2-E-4 - promise api', (done) => {
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00'});

      V2.__encrypt(message, symmetricKey, '', nonce2)
        .then((token) => {
          assert.equal(token, 'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('Test Vector 2-E-5 - callback api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});
      const footer  = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' });

      V2.__encrypt(message, symmetricKey, footer, nonce2, (err, token) => {
        if (err) { return done(err); }
        assert.equal(token, 'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9');

        done();
      });
    });

    it('Test Vector 2-E-5 - promise api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});
      const footer  = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' });

      V2.__encrypt(message, symmetricKey, footer, nonce2)
        .then((token) => {
          assert.equal(token, 'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('Test Vector 2-E-6 - callback api', (done) => {
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00'});
      const footer  = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' });

      V2.__encrypt(message, symmetricKey, footer, nonce2, (err, token) => {
        if (err) { return done(err); }
        assert.equal(token, 'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9');

        done();
      });
    });

    it('Test Vector 2-E-6 - promise api', (done) => {
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00'});
      const footer  = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' });

      V2.__encrypt(message, symmetricKey, footer, nonce2)
        .then((token) => {
          assert.equal(token, 'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('Test Vector 2-S-1 - callback api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});

      V2.sign(message, privateKey, '', (err, token) => {
        if (err) { return done(err); }
        assert.equal(token, 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw');

        return done();
      });
    });

    it('Test Vector 2-S-1 - promise api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});

      V2.sign(message, privateKey, '')
        .then((token) => {
          assert.equal(token, 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw');
          return done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('Test Vector 2-S-2 - callback api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});
      const footer  = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' });

      V2.sign(message, privateKey, footer, (err, token) => {
        if (err) { return done(err); }
        assert.equal(token, 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9');

        return done();
      });
    });

    it('Test Vector 2-S-2 - promise api', (done) => {
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00'});
      const footer  = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' });

      V2.sign(message, privateKey, footer)
        .then((token) => {
          assert.equal(token, 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9');
          return done();
        })
        .catch((err) => {
          return done(err);
        });
    });
  });

  describe('#2E - authenticated encryption', () => {

    // NOTE: Throughout these tests we use the undocumented __encrypt API, allowing us to
    //       provide custom nonce parameters, needed for aligning with known test vectors.

    let sk, nk, fk, nonce;

    before((done) => {
      const skey = Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex');
      sk = new Paseto.SymmetricKey.V2();

      const nkey = Buffer.alloc(32).fill(0);
      nk = new Paseto.SymmetricKey.V2();

      const fkey = Buffer.alloc(32).fill(255, 0, 32);
      fk = new Paseto.SymmetricKey.V2();

      sk.inject(skey, (err) => {
        if (err) { return done(err); }
        nk.inject(nkey, (err) => {
          if (err) { return done(err); }
          fk.inject(fkey, done);
        });
      });
    });

    describe('#1', () => {

      before(() => {
        nonce = Buffer.alloc(24).fill(0);
      });

      it('#1 - Test Vector 2E-1-1 - callback api', (done) => {
        V2.__encrypt('', nk, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ');
          done();
        });
      });

      it('#1 - Test Vector 2E-1-1 - promise api', (done) => {
        V2.__encrypt('', nk, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 2E-1-2 - callback api', (done) => {
        V2.__encrypt('', fk, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg');
          done();
        });
      });

      it('#2 - Test Vector 2E-1-2 - promise api', (done) => {
        V2.__encrypt('', fk, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 2E-1-3 - callback api', (done) => {
        V2.__encrypt('', sk, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA');
          done();
        });
      });

      it('#3 - Test Vector 2E-1-3 - promise api', (done) => {
        V2.__encrypt('', sk, '', nonce)
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
        V2.__encrypt('', nk, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#1 - Test Vector 2E-2-1 - promise api', (done) => {
        V2.__encrypt('', nk, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 2E-2-2 - callback api', (done) => {
        V2.__encrypt('', fk, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#2 - Test Vector 2E-2-2 - promise api', (done) => {
        V2.__encrypt('', fk, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 2E-2-3 - callback api', (done) => {
        V2.__encrypt('', sk, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#3 - Test Vector 2E-2-3 - promise api', (done) => {
        V2.__encrypt('', sk, 'Cuon Alpinus', nonce)
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
        V2.__encrypt('Love is stronger than hate or fear', nk, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0');
          done();
        });
      });

      it('#1 - Test Vector 2E-3-1 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', nk, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 2E-3-2 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', fk, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw');
          done();
        });
      });

      it('#2 - Test Vector 2E-3-2 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', fk, '', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 2E-3-3 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', sk, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U');
          done();
        });
      });

      it('#3 - Test Vector 2E-3-3 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', sk, '', nonce)
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
        V2.__encrypt('Love is stronger than hate or fear', nk, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#1 - Test Vector 2E-4-1 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', nk, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 2E-4-2 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', fk, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#2 - Test Vector 2E-4-2 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', fk, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 2E-4-3 - callback api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', sk, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#3 - Test Vector 2E-4-3 - promise api', (done) => {
        V2.__encrypt('Love is stronger than hate or fear', sk, 'Cuon Alpinus', nonce)
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
        V2.__encrypt(message, sk, footer, nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz');
          done();
        });
      });

      it('promise api', (done) => {
        V2.__encrypt(message, sk, footer, nonce)
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

  describe('#2S - signing', () => {

    let sk, pk;

    before((done) => {
      const skey = Buffer.from('b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2', 'hex');
      sk = new Paseto.PrivateKey.V2();

      const pkey = Buffer.from('1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2', 'hex');
      pk = new Paseto.PublicKey.V2();

      sk.inject(skey, (err) => {
        if (err) { return done(err); }
        pk.inject(pkey, done);
      });
    });

    it('#1 - Test Vector 2S-1 - callback api', (done) => {
      V2.sign('', sk, '', (err, token) => {
        if (err) { return done(err); }

        assert.equal(token, 'v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA');
        done();
      });
    });

    it('#1 - Test Vector 2S-1 - promise api', (done) => {
      V2.sign('', sk, '')
        .then((token) => {
          assert.equal(token, 'v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('#2 - Test Vector 2S-2 - callback api', (done) => {
      V2.sign('', sk, 'Cuon Alpinus', (err, token) => {
        if (err) { return done(err); }

        assert.equal(token, 'v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz');
        done();
      });
    });

    it('#2 - Test Vector 2S-2 - promise api', (done) => {
      V2.sign('', sk, 'Cuon Alpinus')
        .then((token) => {
          assert.equal(token, 'v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('#3 - Test Vector 2S-3 - callback api', (done) => {
      V2.sign('Frank Denis rocks', sk, '', (err, token) => {
        if (err) { return done(err); }

        assert.equal(token, 'v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM');
        done();
      });
    });

    it('#3 - Test Vector 2S-3 - promise api', (done) => {
      V2.sign('Frank Denis rocks', sk, '')
        .then((token) => {
          assert.equal(token, 'v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('#4 - Test Vector 2S-4 - callback api', (done) => {
      V2.sign('Frank Denis rockz', sk, '', (err, token) => {
        if (err) { return done(err); }

        assert.equal(token, 'v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML');
        done();
      });
    });

    it('#4 - Test Vector 2S-4 - promise api', (done) => {
      V2.sign('Frank Denis rockz', sk, '')
        .then((token) => {
          assert.equal(token, 'v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    it('#5 - Test Vector 2S-5 - callback api', (done) => {
      V2.sign('Frank Denis rocks', sk, 'Cuon Alpinus', (err, token) => {
        if (err) { return done(err); }

        assert.equal(token, 'v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz');
        done();
      });
    });

    it('#5 - Test Vector 2S-5 - promise api', (done) => {
      V2.sign('Frank Denis rocks', sk, 'Cuon Alpinus')
        .then((token) => {
          assert.equal(token, 'v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz');
          done();
        })
        .catch((err) => {
          return done(err);
        });
    });

    describe('json test', () => {

      let message, footer;

      before(() => {
        message = JSON.stringify({ data: 'this is a signed message', expires: '2019-01-01T00:00:00+00:00' });
        footer  = 'Paragon Initiative Enterprises';
      });

      it('callback api', (done) => {
        V2.sign(message, sk, footer, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz');
          done();
        });
      });

      it('promise api', (done) => {
        V2.sign(message, sk, footer)
          .then((token) => {
            assert.equal(token, 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });
  });
});
