import {JWK, KeyOperation} from "@lib/jwk/jwk";
import {JWKParser} from "@lib/jwk/jwk-parser";
import * as crypto from "crypto";
import {SigningAlgorithms} from "@lib/jwa";

export default class RSAGenerator {

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

        const { privateKey} = crypto.generateKeyPairSync('rsa', {
            modulusLength: this.getModulusLength(),
            publicExponent: 0x10001, // 65537
        });

        if(this.keyOps?.find((entry) => entry === 'verify')) {
            publicJWK = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
        }
        if(this.keyOps?.find((entry) => entry === 'sign')) {
            privateJWK = privateKey.export({format: 'jwk'});
        }


        return new JWKParser().parse(JSON.stringify({...privateJWK, ...publicJWK}));
    }

    private getModulusLength() : number {
        switch (this.alg) {
            case SigningAlgorithms.RS256:
                return 2048;
            case SigningAlgorithms.RS384:
                return 3072;
            case SigningAlgorithms.RS512:
                return 4096;
            default:
                throw new Error(`unsupported algorithm ${this.alg}`);
        }
    }
}