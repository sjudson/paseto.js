const assert = require('assert');

describe('utilities', () => {

  describe('pae', () => {

    const pae = require('../lib/utils').pae;

    it('should encode no inputs', () => {
      const encoded  = pae();
      const expected = '0000000000000000';

      assert.equal(encoded.toString('hex'), expected);
    });

    it('should encode an empty string', () => {
      const encoded  = pae('');
      const expected = '01000000000000000000000000000000';

      assert.equal(encoded.toString('hex'), expected);
    });

    it('should encode empty strings', () => {
      const encoded  = pae('', '');
      const expected = '020000000000000000000000000000000000000000000000';

      assert.equal(encoded.toString('hex'), expected);
    });

    it('should encode a non-empty string', () => {
      const encoded  = pae('Paragon');
      const expected = '0100000000000000070000000000000050617261676f6e';

      assert.equal(encoded.toString('hex'), expected);
    });

    it('should encode non-empty strings', () => {
      const encoded  = pae('Paragon', 'Initiative');
      const expected = '0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665';

      assert.equal(encoded.toString('hex'), expected);
    });

    it('should ensure faked padding results in different prefixes', () => {
      const padding = Buffer.alloc(7).fill(0);
      const str     = 'Paragon' + String.fromCharCode(10) + padding + 'Initiative';

      const encoded  = pae(str);
      const expected = '0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665';

      assert.equal(encoded.toString('hex'), expected);
    });
  });
});
