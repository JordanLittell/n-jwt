import {AESEncrypter} from "@lib/encryption/aes-encrypter";
import {Encrypter} from "@lib/encryption/encrypter";
import {randomBytes} from "crypto";
import {equal} from "assert";

describe("AES key wrapping", () => {


    it('It correctly encrypts/decrypts with 128 bit keys', () => {
        const key = randomBytes(16);

        let data = "this is my secret. shhhhhh";

        const encrypter : Encrypter = new AESEncrypter({
            kek: key,
            key: Buffer.from(data),
            keySize: 128
        });

        const cipherText = encrypter.encrypt();
        const plainText = encrypter.decrypt(Buffer.from(cipherText));

        equal(plainText.equals(Buffer.from(data)), true);

        equal(plainText, data);
    });

    it('It correctly encrypts/decrypts with 256 bit keys', () => {
        const key = randomBytes(256/8);

        let data = "this is my secret. shhhhhh";

        const encrypter : Encrypter = new AESEncrypter({
            kek: key,
            key: Buffer.from(data),
            keySize: 256
        });

        const cipherText = encrypter.encrypt();
        const plainText = encrypter.decrypt(Buffer.from(cipherText));

        equal(plainText.equals(Buffer.from(data)), true);

        equal(plainText, data);
    });

    it('It correctly encrypts/decrypts with 512 bit keys', () => {
        const key = randomBytes(192/8);

        let data = "this is my secret. shhhhhh";

        const encrypter : Encrypter = new AESEncrypter({
            kek: key,
            key: Buffer.from(data),
            keySize: 192
        });

        const cipherText = encrypter.encrypt();
        const plainText = encrypter.decrypt(Buffer.from(cipherText));

        equal(plainText.equals(Buffer.from(data)), true);

        equal(plainText, data);
    });

});