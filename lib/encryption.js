"use strict";

//this should be grabbed from an environment variable.
const secret = "akdjfopiap oainv3208u9842hpoagnpovu n4qap9u8h4pa";

const algorithm = 'aes-256-ctr';

const crypto = require('crypto');

class Encryption {

  // create a random value to use as a salt
  salt() {
    return crypto.randomBytes(32).toString('hex').slice(32);
  }

  // Create a cryptographic hash using salt
  digest(plaintext) {
    const hash = crypto.createHash('sha256');
    hash.update(plaintext);
    hash.update(secret);
    return hash.digest('hex');
  }

  encypher(plaintext) {
    const cipher = crypto.createCypher(algorithm, secret);
    var encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  decrypt(crypttext) {
    const decipher = crypto.createCipher(algorithm, secret);
    var deciphered = decipher.update(crypttext, 'hex', 'utf8');
    deciphered += decipher.final('utf8');
    return deciphered;
  }
}

module.exports = new Encryption();
