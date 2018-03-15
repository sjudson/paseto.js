const assert = require('assert');

describe('Protocol V1 Test Vectors', () => {

  const _V1 = require('../lib/protocol/V1');
  const V1  = new _V1();

  describe('#1E - authenticated encryption', () => {

    // NOTE: Throughout these tests we use the undocumented __encrypt API, allowing us to
    //       provide custom nonce parameters, needed for aligning with known test vectors.

    let symmetricKey, nullKey, fullKey, nonce;

    before(() => {
      const SymmetricKeyV1 = require('../lib/key/symmetric').V1;

      const skey   = Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex');
      symmetricKey = new SymmetricKeyV1(skey);

      const nkey = Buffer.alloc(32).fill(0);
      nullKey    = new SymmetricKeyV1(nkey);

      const fkey = Buffer.alloc(32).fill(255, 0, 32);
      fullKey    = new SymmetricKeyV1(fkey);
    });

    describe('#1', () => {

      before(() => {
        nonce = Buffer.alloc(32).fill(0);
      });

      it('#1 - Test Vector 1E-1-1 - callback api', (done) => {
        V1.__encrypt('', nullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXyNMehtdOLJS_vq4YzYdaZ6vwItmpjx-Lt3AtVanBmiMyzFyqJMHCaWVMpEMUyxUg');
          done();
        });
      });

      it('#1 - Test Vector 1E-1-1 - promise api', (done) => {
        V1.__encrypt('', nullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXyNMehtdOLJS_vq4YzYdaZ6vwItmpjx-Lt3AtVanBmiMyzFyqJMHCaWVMpEMUyxUg');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 1E-1-2 - callback api', (done) => {
        V1.__encrypt('', fullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTWgetvu2STfe7gxkDpAOk_IXGmBeea4tGW6HsoH12oKElAWap57-PQMopNurtEoEdk');
          done();
        });
      });

      it('#2 - Test Vector 1E-1-2 - promise api', (done) => {
        V1.__encrypt('', fullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTWgetvu2STfe7gxkDpAOk_IXGmBeea4tGW6HsoH12oKElAWap57-PQMopNurtEoEdk');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 1E-1-3 - callback api', (done) => {
        V1.__encrypt('', symmetricKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTV8OmiMvoZgzer20TE8kb3R0QN9Ay-ICSkDD1-UDznTCdBiHX1fbb53wdB5ng9nCDY');
          done();
        });
      });

      it('#3 - Test Vector 1E-1-3 - promise api', (done) => {
        V1.__encrypt('', symmetricKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTV8OmiMvoZgzer20TE8kb3R0QN9Ay-ICSkDD1-UDznTCdBiHX1fbb53wdB5ng9nCDY');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('#2', () => {

      before(() => {
        nonce = Buffer.alloc(32).fill(0);
      });

      it('#1 - Test Vector 1E-2-1 - callback api', (done) => {
        V1.__encrypt('', nullKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVhyXOB4vmrFm9GvbJdMZGArV5_10Kxwlv4qSb-MjRGgFzPg00-T2TCFdmc9BMvJAA.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#1 - Test Vector 1E-2-1 - promise api', (done) => {
        V1.__encrypt('', nullKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVhyXOB4vmrFm9GvbJdMZGArV5_10Kxwlv4qSb-MjRGgFzPg00-T2TCFdmc9BMvJAA.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 1E-2-2 - callback api', (done) => {
        V1.__encrypt('', fullKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVna3s7WqUwfQaVM8ddnvjPkrWkYRquX58-_RgRQTnHn7hwGJwKT3H23ZDlioSiJeo.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#2 - Test Vector 1E-2-2 - promise api', (done) => {
        V1.__encrypt('', fullKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVna3s7WqUwfQaVM8ddnvjPkrWkYRquX58-_RgRQTnHn7hwGJwKT3H23ZDlioSiJeo.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 1E-2-3 - callback api', (done) => {
        V1.__encrypt('', symmetricKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTW9MRfGNyfC8vRpl8xsgnsWt-zHinI9bxLIVF0c6INWOv0_KYIYEaZjrtumY8cyo7M.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#3 - Test Vector 1E-2-3 - promise api', (done) => {
        V1.__encrypt('', symmetricKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTW9MRfGNyfC8vRpl8xsgnsWt-zHinI9bxLIVF0c6INWOv0_KYIYEaZjrtumY8cyo7M.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('#3', () => {

      before(() => {
        nonce = Buffer.alloc(32).fill(0);
      });

      it('#1 - Test Vector 1E-3-1 - callback api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', nullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA45LtwQCqG8LYmNfBHIX-4Uxfm8KzaYAUUHqkxxv17MFxsEvk-Ex67g9P-z7EBFW09xxSt21Xm1ELB6pxErl4RE1gGtgvAm9tl3rW2-oy6qHlYx2');
          done();
        });
      });

      it('#1 - Test Vector 1E-3-1 - promise api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', nullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA45LtwQCqG8LYmNfBHIX-4Uxfm8KzaYAUUHqkxxv17MFxsEvk-Ex67g9P-z7EBFW09xxSt21Xm1ELB6pxErl4RE1gGtgvAm9tl3rW2-oy6qHlYx2');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 1E-3-2 - callback api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', fullKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47lQ79wMmeM7sC4c0-BnsXzIteEQQBQpu_FyMznRnzYg4gN-6Kt50rXUxgPPfwDpOr3lUb5U16RzIGrMNemKy0gRhfKvAh1b8N57NKk93pZLpEz');
          done();
        });
      });

      it('#2 - Test Vector 1E-3-2 - promise api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', fullKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47lQ79wMmeM7sC4c0-BnsXzIteEQQBQpu_FyMznRnzYg4gN-6Kt50rXUxgPPfwDpOr3lUb5U16RzIGrMNemKy0gRhfKvAh1b8N57NKk93pZLpEz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 1E-3-3 - callback api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', symmetricKey, '', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47hvAicYf1zfZrxPrLeBFdbEKO3JRQdn3gjqVEkR1aXXttscmmZ6t48tfuuudETldFD_xbqID74_TIDO1JxDy7OFgYI_PehxzcapQ8t040Fgj9k');
          done();
        });
      });

      it('#3 - Test Vector 1E-3-3 - promise api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', symmetricKey, '', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47hvAicYf1zfZrxPrLeBFdbEKO3JRQdn3gjqVEkR1aXXttscmmZ6t48tfuuudETldFD_xbqID74_TIDO1JxDy7OFgYI_PehxzcapQ8t040Fgj9k');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });

    describe('#4', () => {

      before(() => {
        nonce = Buffer.from('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2', 'hex');
      });

      it('#1 - Test Vector 1E-4-1 - callback api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', nullKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYbivwqsESBnr82_ZoMFFGzolJ6kpkOihkulB4K_JhfMHoFw4E9yCR6ltWX3e9MTNSud8mpBzZiwNXNbgXBLxF_Igb5Ixo_feIonmCucOXDlLVUT.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#1 - Test Vector 1E-4-1 - promise api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', nullKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYbivwqsESBnr82_ZoMFFGzolJ6kpkOihkulB4K_JhfMHoFw4E9yCR6ltWX3e9MTNSud8mpBzZiwNXNbgXBLxF_Igb5Ixo_feIonmCucOXDlLVUT.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#2 - Test Vector 1E-4-2 - callback api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', fullKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYZ8rQTA12SNb9cY8jVtVyikY2jj_tEBzY5O7GJsxb5MdQ6cMSnDz2uJGV20vhzVDgvkjdEcN9D44VaHid26qy1_1YlHjU6pmyTmJt8WT21LqzDl.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#2 - Test Vector 1E-4-2 - promise api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', fullKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYZ8rQTA12SNb9cY8jVtVyikY2jj_tEBzY5O7GJsxb5MdQ6cMSnDz2uJGV20vhzVDgvkjdEcN9D44VaHid26qy1_1YlHjU6pmyTmJt8WT21LqzDl.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });

      it('#3 - Test Vector 1E-4-3 - callback api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', symmetricKey, 'Cuon Alpinus', nonce, (err, token) => {
          if (err) { return done(err); }

          assert.equal(token, 'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz');
          done();
        });
      });

      it('#3 - Test Vector 1E-4-3 - promise api', (done) => {
        V1.__encrypt('Love is stronger than hate or fear', symmetricKey, 'Cuon Alpinus', nonce)
          .then((token) => {
            assert.equal(token, 'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz');
            done();
          })
          .catch((err) => {
            return done(err);
          });
      });
    });
  });
});
