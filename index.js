let crypto = require('crypto')
  , NodeRSA = require('node-rsa')
  , aes = require('aes-js')
  , crypto2 = require('crypto2');

let constants = require('./constants');

function signCert(key, cert, alg) {
  let hashAlg = alg ? alg : constants.signatureHashAlg;
  let sign = crypto.createSign(hashAlg);
  sign.update(cert);

  return sign.sign(key, 'hex');
}

function verifyCert(pub, cert, sig, alg) {
  let hashAlg = alg ? alg : constants.signatureHashAlg;
  let verify = crypto.createVerify(hashAlg);
  verify.update(cert);

  return verify.verify(pub, new Buffer(sig, 'hex'));
}

function generateKeyPair(scheme) {
  let es = scheme ? scheme : constants.encryptionScheme;
  let key = new NodeRSA({ b: 1024 });
  return { pubKey: key.exportKey(`${es}-public-pem`), privKey: key.exportKey(`${es}-pem`) }
}

function generateHash(buf, saltSize, hashIterations, hmacSize, hmacDigestAlg) {
  let saltSize_ = saltSize ? saltSize : constants.saltSize;
  let salt = crypto.randomBytes(saltSize_).toString('hex');
  let iterations = hashIterations ? hashIterations : constants.hashIterations;
  let keyLen = hmacSize ? hmacSize : constants.hmacSize;
  let digest = hmacDigestAlg ? hmacDigestAlg : constants.hmacDigestAlg;

  let hash = crypto.pbkdf2Sync(buf, salt, iterations, keyLen, digest).toString('hex');
  return 'pbkdf2_' + digest + '$' + iterations + '$' + salt + '$' + hash;
}

function checkHashValidity(buf, hash) {
  let params = hash.split('$');
  let digest = params[0].split('_')[1];
  let iterations = parseInt(params[1]);
  let salt = params[2];
  let prev_hash = params[3];
  let hash_ = crypto.pbkdf2Sync(buf, salt, iterations, prev_hash.length/2, digest).toString('hex');
  return prev_hash === hash_;
}

function generatePubKey(privKey, scheme) {
  let es = scheme ? scheme : constants.encryptionScheme;
  try {
    let key = NodeRSA(privKey);
    return { pubKey: key.exportKey(`${es}-public-pem`), privKey: key.exportKey(`${es}-pem`) }
  } catch (err) {
    return null
  }
}

function isKeyPairValid(privKey, pubKey) {
  try {
    const sig = signCert(privKey,'FOOBARFOO');
    return verifyCert(pubKey, 'FOOBARFOO', sig);
  } catch (err) {
    return false
  }
}

// Returns promise. Call by createEncryptedPrivkey(...).then( response => console.log(response))
// returns { privkeyEncrypted: string, iv: string }
async function createEncryptedPrivkey(password, privKeyPlaintext) {

    const iv = await crypto2.createIv();

    const pass = await getPasswordLen32(password);

    const privkeyEncrypted = await crypto2.encrypt(privKeyPlaintext, pass, iv);

    return {
        privkeyEncrypted,
        iv
    }
}

// Returns promise. Call like this: decryptEncryptedPrivkey(...).then( response => console.log(response))
async function decryptEncryptedPrivkey(encryptedPrivKey, password, iv) {

    const pass = await getPasswordLen32(password);

    return crypto2.decrypt(encryptedPrivKey, pass, iv);
}

async function getPasswordLen32 (password) {

    const passwordHash = await crypto2.hash(password);

    let passLen32 = '';

    // Password must be of length 32
    for (let i = 0; i < 32; i++) {
        passLen32 += passwordHash[i];
    }

    return passLen32;
}


module.exports = {
  signCert,
  verifyCert,
  generateKeyPair,
  generateHash,
  checkHashValidity,
  isKeyPairValid,
  generatePubKey,
  createEncryptedPrivkey,
  decryptEncryptedPrivkey,
};



