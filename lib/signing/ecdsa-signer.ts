import {Signer} from "@lib/signing/signer";
import {SigningAlgorithms, ECDSADigests} from "@lib/jwa";
import {JWK} from "@lib/jwk/jwk";
import {createPrivateKey, createSign} from "crypto";

export class ECDSASigner implements Signer {

    readonly algorithm: SigningAlgorithms;

    constructor(algorithm: SigningAlgorithms) {
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

    private isECDSAAlgorithm(algorithm: SigningAlgorithms) : boolean {
        return new Set([SigningAlgorithms.ES256, SigningAlgorithms.ES512, SigningAlgorithms.ES384]).has(algorithm);
    }
}