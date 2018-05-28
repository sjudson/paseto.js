const assert = require('assert');

const extcrypto = require('../extcrypto');

describe('extcrypto', () => {

  describe('keygen', () => {

    it('should generate a pem encoded key synchronously', (done) => {
      const sk = extcrypto.keygen();

      assert.ok(typeof sk === 'string');
      assert.equal('-----BEGIN RSA PRIVATE KEY-----', sk.slice(0, 31));

      done();
    });

    it('should generate a pem encoded key asynchronously', (done) => {
      extcrypto.keygen((err, sk) => {
        assert.ok(!err);

        assert.ok(typeof sk === 'string');
        assert.equal('-----BEGIN RSA PRIVATE KEY-----', sk.slice(0, 31));

        done();
      });
    });
  });

  describe('extract', () => {

    const expected = {
      sk: `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQB/PtUvNESWIxNMyEEvRU1a+mKTt0HuycrDPqND6lsC3JIvoFos
o9lpcvRNFR4F0C8lr5Zzp7I9tL+w5uciJL1ZNEr6wOCMHGTdDNSYqsTD/ParSXzi
RilECa/68NMYtt2mbDUqk3aOlAFqVoTfo5pWOmBM3cYMoKF68uW5vDVr28iPQwN5
WkS8mLd+UfGfP3PF4DNSPDYuAn5C+tgHpOlhZrMQm8lkoUvhCiE1m1kpwBXtsMq6
QjyU6u1MkDo/vnESS2d891Zzp+z56bCnTtQkFxABBCR7stw/w+X2x2SncVEMESAC
/c+cDVcX9MmiYMvNo0DgKxt3Ku8PenXw9LaLAgMBAAECggEAeP5ZHjqYIR8XIgKl
IPrH9INzqrwt4I5W1FLCUjkM82qjQtA6Dop6mC9rp8Q1uRddTXtqF21VKiGtyNu2
2huPRLxZs5glrHTvX9XsbYKr+SSXtQX6zvoiEQUZJgdK4ww3NSFdaK+xox+PPPsp
+7GIdwepPE4BHU68XbmLwZH6RiTuC5YnI6Ir/m7T0jlJkHUu0nubhaUeXmNqXoA8
jG7cjfOiK0B0fatq6u+ysGilTBnpzfRb2JBUN7MkDgrfH2eFtV9fW18I0kvH/fSD
bwWZ5WjT29Rx3JWNfl5Q2YlywUM8skxuz4+bWCknk3W/56lNVLv44ZGDplogbfLz
kEtA8QKBgQC+v/RgF8K3MCOgzydvKW2ZwD7zpe9A7ups0rA5+UiqIYHBlNkDZXv1
TEFixx/qhg7EpELgmwUqllqrvy4RM/QdykVvqarksF9Qk8X6e5v1OYYH6qMq9iDf
Tt9h+d0tb2F6KShpgXJDP2ZI1So4AeKR97jy3zVv9XXMraKvnUjBWQKBgQCqxcWJ
ujrKg2/XdAjeraUPh8p+SV1FWuPLYXNm1lumxc2NO0lwk/J9oGUgL47gbs8jWfWa
gTCN1K5A/zeaxpNcA/P0mgTNvox4Y5tcRcOWMA0E3TCQFs7S0lq1+7bRpz3Yapz0
0Q7ytMi+HFnjZDT3rPgjVNkbHkUAoV0ehFk2gwKBgQCJqH3z2zHqghM0Okt7Laqr
CtJjg5zmf4Uug94p+H04SnYZ/hGfId4TaLTHVGz0E0sVHnYlIbrYwSkuSQo14AiM
dy0lKIzr/VzMCdkWq54hmyHfFLYsivOuNH2Bd5Dm+TqfrpQ7j++mGFr4tN2DDdk0
/lG69NrbsYkR7T06/4dCAQKBgHxAkc34FjarE4EsCBgdN+/o2UixkI+Z5gxgx1qX
tO/PFBQigvjKbLFDNtEISWi6tzP9jFnyjaVkjbT0/Tw8J5PXvHTIa55XelVOBAhL
KlfodlCHr4HnVmzGaQHoN8irarBAQhtO0RV+vGC2uCBfFLrwu0rZvW2hxIsE3YAK
w+6JAoGAG6dhOcSatNj4ZLvmpKhbg5bxMg7kkpRC4Rj9UYUs+zyiCid6J8XQOv8k
EeRCKOoBGerQvOJisPfFLS9q3K+FeS7eY7ILnlVw/SH1TJRyGBEFvHYw6HtQuKlt
i49Rflp4xaH7OCfsKw5ksQDTMOSjnQK3gDdz+kHYJ7FuSlTVwrc=
-----END RSA PRIVATE KEY-----\n`,
      pk: `-----BEGIN RSA PUBLIC KEY-----
MIIBCQKCAQB/PtUvNESWIxNMyEEvRU1a+mKTt0HuycrDPqND6lsC3JIvoFoso9lp
cvRNFR4F0C8lr5Zzp7I9tL+w5uciJL1ZNEr6wOCMHGTdDNSYqsTD/ParSXziRilE
Ca/68NMYtt2mbDUqk3aOlAFqVoTfo5pWOmBM3cYMoKF68uW5vDVr28iPQwN5WkS8
mLd+UfGfP3PF4DNSPDYuAn5C+tgHpOlhZrMQm8lkoUvhCiE1m1kpwBXtsMq6QjyU
6u1MkDo/vnESS2d891Zzp+z56bCnTtQkFxABBCR7stw/w+X2x2SncVEMESAC/c+c
DVcX9MmiYMvNo0DgKxt3Ku8PenXw9LaLAgMBAAE=
-----END RSA PUBLIC KEY-----\n`
    }

    it('should extract a public key from secret key synchronously', (done) => {
      const pk = extcrypto.extract(expected.sk);

      assert.ok(typeof pk === 'string');
      assert.equal(expected.pk, pk);

      done();
    });

    it('should extract a public key from secret key asynchronously', (done) => {
      extcrypto.extract(expected.sk, (err, pk) => {
        assert.ok(!err);

        assert.ok(typeof pk === 'string');
        assert.equal(expected.pk, pk);

        done();
      });
    });
  });
});
