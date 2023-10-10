import {Signer} from "@lib/signing/signer";
import {Algorithm, ECDSADigests} from "@lib/jwa";
import {JWK} from "@lib/jwk/jwk";
import {constants, createPrivateKey, createSign} from "crypto";
import {NodeAlgorithmMappings} from "@lib/node-algorithm-mappings";

export class ECDSASigner implements Signer {

    readonly algorithm: Algorithm;

    constructor(algorithm: Algorithm) {
        this.algorithm = algorithm;
    }

    sign(message: string, jwk: JWK): string {
        if(!this.isECDSAAlgorithm(this.algorithm)) throw new Error(`Unsupported algorithm ${this.algorithm}!`);

        if(jwk.getKeyType() == 'ECPrivate') {
            const key = createPrivateKey({
                key: JSON.parse(jwk.serialize()),
                format: "jwk",
                encoding: "utf8"
            });

            const signer = createSign(ECDSADigests[this.algorithm]);
            signer.update(message);
            signer.end();
            return signer.sign({key: key}, "base64url");
        }

        throw new Error("Expected JWK to have ECDSA Private Key parameters");
    }

    private isECDSAAlgorithm(algorithm: Algorithm) : boolean {
        return new Set([Algorithm.ES256, Algorithm.ES512, Algorithm.ES384]).has(algorithm);
    }
}