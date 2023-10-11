export interface Encrypter {
    encrypt () : Buffer;
    decrypt (cipherText: Buffer) : Buffer;
}