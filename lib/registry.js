const Version1 = Object(Symbol('Version1'));
Version1.header = 'v1';

const Version2 = Object(Symbol('Version2'));
Version2.header = 'v2';

module.exports.protocol = { Version1: Version1, Version2: Version2 }
