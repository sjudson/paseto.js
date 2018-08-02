'use strict';

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var utils = require('./utils');

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
  var parsed = Buffer.from(token, 'utf-8');

  var hlen = Buffer.byteLength(header);
  var leading = parsed.slice(0, hlen);

  if (!utils.cnstcomp(header, leading)) {
    throw new Error('Invalid message header');
  }

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
  var pieces = token.split('.');

  return pieces.length > 3 ? utils.fromB64URLSafe(pieces.pop()) : Buffer.from('');
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
  var pieces = token.split('.');

  return pieces.length > 3 ? pieces.slice(0, 3).join('.') : token;
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
  if (!footer) {
    return token;
  }
  footer = Buffer.concat([Buffer.from('.', 'utf-8'), footer]);

  var trailing = Buffer.concat([Buffer.from('.', 'utf-8'), extract(token)]);

  if (!utils.cnstcomp(footer, trailing)) {
    throw new Error('Invalid message footer');
  }

  return remove(token);
}

/***
 * decapsulate
 *
 * validate and remove headers and footers
 *
 * @param {Buffer} header
 * @param {String} token
 * @param {String|Buffer} footer
 * @returns {Array} parsed
 */
module.exports = decapsulate;
function decapsulate(header, token, footer) {
  if (!footer) {
    footer = extract(token);
    token = remove(token);
  } else {
    var _utils$parse = utils.parse('utf-8')(footer);

    var _utils$parse2 = _slicedToArray(_utils$parse, 1);

    footer = _utils$parse2[0];

    token = fvalidate(token, footer);
  }

  var payload = hvalidate(token, header);

  var _utils$parse3 = utils.parse('base64')(payload);

  var _utils$parse4 = _slicedToArray(_utils$parse3, 1);

  payload = _utils$parse4[0];


  return [header, payload, footer];
}