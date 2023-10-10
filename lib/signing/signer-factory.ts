import {Algorithm} from "@lib/jwa";
import {HMACSigner} from "@lib/signing/hmac-signer";
import {Signer} from "@lib/signing/signer";
import {RSASigner} from "@lib/signing/rsa-signer";
import {ECDSASigner} from "@lib/signing/ecdsa-signer";

/**
 * Abstract factory that constructs implementations of Signer
 */
export class SignerFactory {
    private readonly signingAlgorithm: Algorithm;

    constructor(signingAlgorithm: Algorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    create() : Signer {
        switch (this.signingAlgorithm) {

            case Algorithm.HS256:
            case Algorithm.HS384:
            case Algorithm.HS512:
                return new HMACSigner(this.signingAlgorithm);
            case Algorithm.RS256:
            case Algorithm.RS384:
            case Algorithm.RS512:
                return new RSASigner(this.signingAlgorithm);
            case Algorithm.ES256:
            case Algorithm.ES384:
            case Algorithm.ES512:
                return new ECDSASigner(this.signingAlgorithm);
            default:
                throw new Error(`unsupported algorithm ${this.signingAlgorithm}!`);
        }
    }
}