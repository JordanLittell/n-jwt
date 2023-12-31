import * as crypto from "crypto";
import {Signer} from "@lib/signing/signer";
import {JWK} from "@lib/jwk/jwk";
import {NodeAlgorithmMappings} from "@lib/node-algorithm-mappings";
import {SigningAlgorithms} from "@lib/jwa";

/**
 * Signing algorithm is derived from JOSE headers. The JWK is used to get the parameters for the signing algorithm.
 * The algorithm specified must agree with the signing parameters present on the JWK otherwise an error is thrown.
 */
export class HMACSigner implements Signer {

    readonly algorithm: SigningAlgorithms;

    constructor(algorithm: SigningAlgorithms) {
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
        if(!this.isHMACAlgorithm(this.algorithm)) throw new Error(`Unsupported algorithm ${this.algorithm}!`);


        if(jwk.getKeyType() == 'Octet') {
            const hmac = crypto.createHmac(NodeAlgorithmMappings[this.algorithm], jwk.k!);
            hmac.write(message);
            return hmac.digest('base64url');
        }

        throw new Error("Expected to find JWK key parameter 'k'");
    }

    private isHMACAlgorithm(algorithm: SigningAlgorithms) : boolean {
        return new Set([SigningAlgorithms.HS512, SigningAlgorithms.HS384, SigningAlgorithms.HS256]).has(algorithm);
    }

}