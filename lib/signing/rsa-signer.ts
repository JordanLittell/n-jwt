import {Signer} from "./signer";
import {JWK} from "../jwk/jwk";
import {constants, createPrivateKey, createSign} from "crypto";
import {Algorithm} from "../jwa";
import {CryptoKeyParam, isRSAPrivate} from "../jwk/crypto-key-params";
import {NodeAlgorithmMappings} from "../node-algorithm-mappings";

export class RSASigner implements Signer {

    readonly algorithm: Algorithm;

    constructor(algorithm: Algorithm) {
        this.algorithm = algorithm;
    }

    sign(message: string, jwk: JWK): string {
        if(!this.isRSAAlgorithm(this.algorithm)) throw new Error(`Unsupported algorithm ${this.algorithm}!`);

        const keyParams : CryptoKeyParam =  jwk.key_params;

        if(isRSAPrivate(keyParams)) {
            const key = createPrivateKey({
                key: JSON.parse(jwk.serialize()),
                format: "jwk",
                encoding: "utf8"
            });

            const signer = createSign(NodeAlgorithmMappings[this.algorithm]);
            signer.update(message);
            return signer.sign({key: key, padding: constants.RSA_PKCS1_PADDING}, "base64url");
        }

        throw new Error("Expected JWK to have RSA Private Key parameters")
    }

    private isRSAAlgorithm(algorithm: Algorithm) : boolean {
        return new Set([Algorithm.RS256, Algorithm.RS512, Algorithm.RS384]).has(algorithm);
    }
}