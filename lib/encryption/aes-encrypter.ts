import {Encrypter} from "@lib/encryption/encrypter";
import {createCipheriv, createDecipheriv} from "crypto";

export type AESKeySize = 128 | 192 | 256;

export interface AESParams {
    keySize: AESKeySize,
    kek: Buffer,
    key: Buffer
}

export class AESEncrypter implements Encrypter {

    readonly iv : Buffer;
    readonly kek : Buffer;
    readonly key: Buffer;
    readonly keySize: AESKeySize;

    constructor(params: AESParams) {
        this.iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
        this.kek = params.kek;
        this.key = params.key;
        this.keySize = params.keySize;
    }

    encrypt(): Buffer {
        const cipher = createCipheriv(this.getAlg(), this.kek, this.iv);
        return cipher.update(this.key);
    }

    decrypt(cipherText: Buffer) : Buffer {
        const decipher = createDecipheriv(this.getAlg(), this.kek, this.iv);
        return decipher.update(cipherText);
    }

    private getAlg() : string {
        switch (this.keySize) {
            case(128):
                return 'aes-128-gcm';
            case(256):
                return 'aes-256-gcm';
            case(192):
                return 'aes-192-gcm';
            default:
                throw new Error(`Key size: ${this.keySize} not supported!!`);
        }
    }

}