import * as crypto from "crypto";
import {Signer} from "./signer";
import {JWK} from "../jwk/jwk";
import {CryptoKeyParam, isOctet} from "../jwk/crypto-key-params";
import {NodeAlgorithm} from "../crypto-node-algorithms";
import {Algorithm} from "../jwa";

/**
 * Signing algorithm is derived from JOSE headers. The JWK is used to get the parameters for the signing algorithm.
 * The algorithm specified must agree with the signing parameters present on the JWK otherwise an error is thrown.
 */
export class HMACSigner implements Signer {

    readonly algorithm: Algorithm;

    constructor(algorithm: Algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Compute the JWS Signature in the manner defined for the
     *        particular algorithm being used over the JWS Signing Input
     *        ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
     *        BASE64URL(JWS Payload)).  The "alg" (algorithm) Header Parameter
     *        MUST be present in the JOSE Header, with the algorithm value
     *        accurately representing the algorithm used to construct the JWS
     *        Signature.
     */
    sign(message: string, jwk: JWK): string {
        const keyParams : CryptoKeyParam =  jwk.key_params;
        switch (this.algorithm) {
            // signing with HMAC and SHA2
            case(Algorithm.HS256.valueOf()):
                if(isOctet(keyParams)) {
                    const {k} = keyParams;
                    const hmac = crypto.createHmac(NodeAlgorithm.HS256, k)
                    hmac.update(message)
                    return hmac.digest('base64url')
                }
                throw new Error("Expected to find JWK key parameter 'k' for sha-256");
            case Algorithm.HS384.valueOf():
                if(isOctet(keyParams)) {
                    const hash = crypto.createHash(NodeAlgorithm.HS384);
                    hash.update(message);
                    return hash.digest('base64url');
                }
                throw new Error("Expected to find JWK key parameter 'k' for sha-256");
            case Algorithm.HS512.valueOf():
                if(isOctet(keyParams)) {
                    const hash = crypto.createHash(NodeAlgorithm.HS512);
                    hash.update(message);
                    return hash.digest('base64url');
                }
                throw new Error("Expected to find JWK key parameter 'k' for sha-256");

            default:
                throw new Error(`Unsupported algorithm ${this.algorithm}!`);
        }
    }

}