import {Algorithm} from "../jwa";
import {HMACSigner} from "./hmac-signer";
import {Signer} from "./signer";

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
                return new HMACSigner(this.signingAlgorithm)
            default:
                throw new Error("unsupported algorithm!")
        }
    }
}