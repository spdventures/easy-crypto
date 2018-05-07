declare module "easy-crypto" {
  function generateHash(buf: Blob,
                        saltSize?:number,
                        hashIterations?:number,
                        hmacSize?:number,
                        hmacDigestAlg?:number): string;
  function signCert(key: string,
                    cert: string,
                    alg?: string): string;
  function isKeyPairValid(privKey: string,
                          pubKey: string): boolean
  function generateKeyPair(scheme?: string): {pubKey: string, privKey: string}
  function createEncryptedPrivkey(password: string,
                           privateKeyPlaintext: string): {privkeyEncrypted: string, iv: string}
  function decryptEncryptedPrivkey(password: string, encryptedPrivkey: string, iv: string): string

  export {generateHash, signCert, isKeyPairValid, generateKeyPair, createEncryptedPrivkey, decryptEncryptedPrivkey};
}

