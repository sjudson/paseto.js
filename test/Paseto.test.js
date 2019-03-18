const assert = require('assert');
const sodium = require('libsodium-wrappers-sumo');

const Paseto = require('../lib/paseto');

const notExpired = require('../lib/rules/notexpired')

describe('Paseto', () => {

	const Builder = new Paseto.Builder();
	const Parser = new Paseto.Parser();

	const footer = 'footer';
	const claims = {"first": "1", "second": "2"};

	describe('V2', () => {
		let key, footer;

		describe('claims', () => {
			it('should be able to set the exp claim', () => {
				let time = new Date();
				let tokenBuilder = Builder.setExpiration(time);
				let formattedTime = time.toISOString();

				assert.ok(tokenBuilder.token.get('exp') === formattedTime)
			});
		})

		describe('rules', () => {
			it('should be able to check if a token is expired', () => {
				let time = new Date();
				time.setDate(new Date(time.getDate() + 1));
				let tokenBuilder = Builder.setExpiration(time);

				let isValid;
				isValid = Parser.addRule(new notExpired()).validate(tokenBuilder.token);
				assert.ok(isValid);

				assert.throws(function () {Parser.addRule(new notExpired(time.setDate(time.getDate() + 1))).validate(tokenBuilder.token)}, Error);
			})
		})

		describe('local', () => {
			before((done) => {
				sodium.ready.then(() => {
					footer = 'footer';
					const rkey = Buffer.from(sodium.randombytes_buf(32));

					key = new Paseto.SymmetricKey.V2();
					key.inject(rkey, done);
				})
			});

			it('should be able to encrypt and decrypt a local token', async () => {
				try {
					let tokenBuilder;

					tokenBuilder = Builder.setKey(key).setFooter(footer).setPurpose('local').setFooter(footer).setClaims(claims);

					let decryptedToken;
					decryptedToken = await Parser.setKey(key).parse(await tokenBuilder.toString());
					assert.deepEqual(tokenBuilder.token, decryptedToken);
					return true;
				} catch (Exception) {
					throw Exception;
				}
			});
		})

		describe('public', () => {
	    before((done) => {
	    	let footer = 'footer';
				sodium.ready.then(() => {
		      const keypair = sodium.crypto_sign_keypair();

		      sk = new Paseto.PrivateKey.V2();
		      sk.inject(keypair.privateKey, (err) => {
		        if (err) { return done(err); }

		        pk = new Paseto.PublicKey.V2();
		        pk.inject(keypair.publicKey, done);
		      });
	    	});
	    });

			it('should be able to sign and verify a public token', async () => {
				try {
					let tokenBuilder;
					tokenBuilder = Builder.setKey(sk).setFooter(footer).setPurpose('public').setFooter(footer).setClaims(claims);

					let decryptedToken;
					decryptedToken = await Parser.setKey(pk).parse(await tokenBuilder.toString());
					assert.deepEqual(tokenBuilder.token, decryptedToken);
					return true;
				} catch (Exception) {
					throw Exception;
				}
			});
		})
	})
});
