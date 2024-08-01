const cryptojs = require('crypto-js');

module.exports = function compare (passw, hashpw) {
    const hashpw2 = cryptojs.SHA256(passw).toString();
    return hashpw2 === hashpw;
}