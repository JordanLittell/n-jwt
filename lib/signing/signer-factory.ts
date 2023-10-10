import {SigningAlgorithms} from "@lib/jwa";
import {HMACSigner} from "@lib/signing/hmac-signer";
import {Signer} from "@lib/signing/signer";
import {RSASigner} from "@lib/signing/rsa-signer";
import {ECDSASigner} from "@lib/signing/ecdsa-signer";

/**
 * Abstract factory that constructs implementations of Signer
 */
export class SignerFactory {
    private readonly signingAlgorithm: SigningAlgorithms;

    constructor(signingAlgorithm: SigningAlgorithms) {
        this.signingAlgorithm = signingAlgorithm;
    }

    create() : Signer {
        switch (this.signingAlgorithm) {

            case SigningAlgorithms.HS256:
            case SigningAlgorithms.HS384:
            case SigningAlgorithms.HS512:
                return new HMACSigner(this.signingAlgorithm);
            case SigningAlgorithms.RS256:
            case SigningAlgorithms.RS384:
            case SigningAlgorithms.RS512:
                return new RSASigner(this.signingAlgorithm);
            case SigningAlgorithms.ES256:
            case SigningAlgorithms.ES384:
            case SigningAlgorithms.ES512:
                return new ECDSASigner(this.signingAlgorithm);
            default:
                throw new Error(`unsupported algorithm ${this.signingAlgorithm}!`);
        }
    }
}