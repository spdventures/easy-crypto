let crypto = require('crypto')
    , NodeRSA = require('node-rsa');

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
    let salt = getRandomBytes(16).toString('hex');
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

function encryptPrivkey(password, privkeyPlaintext, alg, inputEnc, outputEnc) {
    let algorithm = alg ? alg : constants.algorithm;
    let inputEncoding = inputEnc ? inputEnc : constants.inputEncoding;
    let outputEncoding = outputEnc ? outputEnc : constants.outputEncoding;
    const iv = getRandomBytes(16);
    const passwordHashed = passwordLength16(password)
    const cipher = crypto.createCipheriv(algorithm, passwordHashed, iv);
    let privkeyEncrypted = cipher.update(privkeyPlaintext, inputEncoding, outputEncoding);
    privkeyEncrypted += cipher.final(outputEncoding);
    return {
        privkeyEncrypted,
        iv: bufferToHexStr(iv)
    };
}

function decryptPrivkey(password, privkeyEncrypted, iv, alg, inputEnc, outputEnc) {
    let algorithm = alg ? alg : constants.algorithm;
    let inputEncoding = inputEnc ? inputEnc : constants.inputEncoding;
    let outputEncoding = outputEnc ? outputEnc : constants.outputEncoding;
    const ivUint8 = hexStrToBuffer(iv);
    const passwordHashed = passwordLength16(password);
    const decipher = crypto.createDecipheriv(algorithm, passwordHashed, ivUint8);
    let decrypted = decipher.update(privkeyEncrypted, outputEncoding, inputEncoding);
    decrypted += decipher.final(inputEncoding);
    return decrypted
}

function getRandomBytes(numBytes) {
    return crypto.randomBytes(numBytes);
}

function passwordLength16(password) {
    const hash = crypto.createHash(constants.hmacDigestAlg);
    hash.update(password);
    const hashedPassword = hash.digest(constants.outputEncoding);
    return hashedPassword.slice(0,16);
}

function bufferToHexStr(uint8Array) {
    return Buffer.from(uint8Array).toString('hex');
}

function hexStrToBuffer(hexStr) {
    return Buffer.from(hexStr, "hex")
}


module.exports = {
    signCert,
    verifyCert,
    generateKeyPair,
    generateHash,
    checkHashValidity,
    isKeyPairValid,
    generatePubKey,
    encryptPrivkey,
    decryptPrivkey,
};
