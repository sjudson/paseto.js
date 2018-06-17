const utils = require('./utils');


/***
 * hvalidate
 *
 * validate (and remove) header
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @param {Buffer} header
 * @returns {String} token
 */
function hvalidate(token, header) {
  const parsed = Buffer.from(token, 'utf-8');

  const hlen    = Buffer.byteLength(header);
  const leading = parsed.slice(0, hlen);

  if (!utils.cnstcomp(header, leading)) { throw new Error('Invalid message header'); }

  return parsed.slice(hlen).toString('utf-8');
}


/***
 * extract
 *
 * extract footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @returns {Buffer} footer
 */
function extract(token) {
  const pieces = token.split('.');

  return (pieces.length > 3)
    ? utils.fromB64URLSafe(pieces.pop())
    : Buffer.from('');
};


/***
 * remove
 *
 * remove footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @returns {String} token
 */
function remove(token) {
  const pieces = token.split('.');

  return (pieces.length > 3)
    ? pieces.slice(0, 3).join('.')
    : token;
};


/***
 * fvalidate
 *
 * validate (and remove) footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @param {Buffer} footer
 * @returns {String} token
 */
function fvalidate(token, footer) {
  if (!footer) { return token; }
  footer = Buffer.concat([ Buffer.from('.', 'utf-8'), footer ]);

  const trailing = Buffer.concat([ Buffer.from('.', 'utf-8'), extract(token) ]);

  if (!utils.cnstcomp(footer, trailing)) { throw new Error('Invalid message footer'); }

  return remove(token);
}


/***
 * decapsulate
 *
 * validate and remove headers and footers
 *
 * @param {Buffer} header
 * @param {String|Buffer} footer
 * @returns {Array} parsed
 */
module.exports = decapsulate;
function decapsulate(header, token, footer) {
  if (!footer) {
    footer = extract(token);
    token  = remove(token);
  } else {
    [ footer ] = (utils.parse('utf-8'))(footer);
    token      = fvalidate(token, footer);
  }

  let payload = hvalidate(token, header);
  [ payload ] = (utils.parse('base64'))(payload);

  return [ header, payload, footer ];
}
