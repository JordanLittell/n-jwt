import {Signer} from "@lib/signing/signer";
import {JWK} from "@lib/jwk/jwk";
import {constants, createPrivateKey, createSign} from "crypto";
import {SigningAlgorithms} from "@lib/jwa";
import {NodeAlgorithmMappings} from "@lib/node-algorithm-mappings";

export class RSASigner implements Signer {

    readonly algorithm: SigningAlgorithms;

    constructor(algorithm: SigningAlgorithms) {
        this.algorithm = algorithm;
    }

    sign(message: string, jwk: JWK): string {
        if(!this.isRSAAlgorithm(this.algorithm)) throw new Error(`Unsupported algorithm ${this.algorithm}!`);

        if(jwk.getKeyType() == 'RSAPrivate') {
            const key = createPrivateKey({
                key: JSON.parse(jwk.serialize()),
                format: "jwk",
                encoding: "utf8"
            });

            const signer = createSign(NodeAlgorithmMappings[this.algorithm]);
            signer.update(message);
            return signer.sign({key: key, padding: constants.RSA_PKCS1_PADDING}, "base64url");
        }

        throw new Error("Expected JWK to have RSA Private Key parameters");
    }

    private isRSAAlgorithm(algorithm: SigningAlgorithms) : boolean {
        return new Set([SigningAlgorithms.RS256, SigningAlgorithms.RS512, SigningAlgorithms.RS384]).has(algorithm);
    }
}