exports = module.exports = new Object();

module.exports.keys = {
  symmetric: require('./key/symmetric')
}

module.exports.protocol = {
  v1: require('./protocol/V1'),
  v2: require('./protocol/V2')
}
