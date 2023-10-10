import {JWK, KeyOperation} from "@lib/jwk/jwk";
import {JWKParser} from "@lib/jwk/jwk-parser";
import * as crypto from "crypto";
import {SigningAlgorithms} from "@lib/jwa";
import {RSAPSSKeyPairKeyObjectOptions} from "crypto";

export default class PSAGenerator {

    private readonly alg : SigningAlgorithms;
    private readonly keyOps? : KeyOperation[];

    constructor (alg: SigningAlgorithms, keyOps?: KeyOperation[]) {
        this.alg = alg;
        this.keyOps = keyOps;
    }
    generate() : JWK {
        if(!this.keyOps)
            throw new Error("With RSA keys, you must indicate the use in keyOps: 'sign', 'verify', or both");

        let publicJWK = {}, privateJWK = {};

        const options: RSAPSSKeyPairKeyObjectOptions = {
            modulusLength: this.getModulusLength(),
            publicExponent: 0x10001, // 65537
            hashAlgorithm: this.getHashFn(),
            saltLength: this.getSaltLength()
        };

        const { privateKey} = crypto.generateKeyPairSync('rsa-pss', options);

        if(this.keyOps?.find((entry) => entry === 'verify')) {
            publicJWK = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
        }
        if(this.keyOps?.find((entry) => entry === 'sign')) {
            privateJWK = privateKey.export({format: 'jwk'});
        }


        return new JWKParser().parse(JSON.stringify({...privateJWK, ...publicJWK}));
    }

    private getSaltLength() : string {
        switch (this.alg) {
            case SigningAlgorithms.PS256:
                return '32';
            case SigningAlgorithms.PS384:
                return '48';
            case SigningAlgorithms.PS512:
                return '64';
            default:
                throw new Error(`unsupported algorithm ${this.alg}`);
        }
    }

    private getHashFn() : string {
        switch (this.alg) {
            case SigningAlgorithms.PS256:
                return 'SHA-256';
            case SigningAlgorithms.PS384:
                return 'SHA-384';
            case SigningAlgorithms.PS512:
                return 'SHA-512';
            default:
                throw new Error(`unsupported algorithm ${this.alg}`);
        }
    }

    private getModulusLength() : number {
        switch (this.alg) {
            case SigningAlgorithms.PS256:
                return 2048;
            case SigningAlgorithms.PS384:
                return 3072;
            case SigningAlgorithms.PS512:
                return 4096;
            default:
                throw new Error(`unsupported algorithm ${this.alg}`);
        }
    }
}