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
  export {generateHash, signCert, isKeyPairValid};
}
