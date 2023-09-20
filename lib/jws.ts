/**
 * JSON Web Signature (JWS) represents content secured with digital signatures or Message Authentication Codes (MACs)
 * using JSON-based data structures.
 * RFC: https://datatracker.ietf.org/doc/html/rfc7515
 */
import {Algorithm} from "./jwa";
import {SignerParams} from "./signing/signer-factory";
import * as crypto from "crypto";
import {Header} from "./jose";
import {btoa} from "buffer";

/**
 * Compute the JWS Signature in the manner defined for the particular algorithm being used over the JWS Signing Input
 * this will be used as the payload for the JWS
 */
class Signer {

    algorithm: string;
    key: string;

    constructor(signingParams: SignerParams) {
        this.algorithm = signingParams.alg;
        this.key = signingParams.kid;
    }

    sign (message: string) {
        switch (this.algorithm) {
            case(Algorithm.HS512.valueOf()):
                const hmac = crypto.createHmac('sha512', this.key)
                hmac.digest('hex')
        }
    }
}

class JWS {

    // Note that the payload can be any content and need not be a representation of a JSON object.
    payload: string;
    headers: Record<Header, string>;
    signature: string;

    constructor(headers: Record<Header, string>, payload: string) {
        this.payload = payload;
    }

    serialize () : string {
        const headerString = JSON.stringify(this.headers);
        const encodedHeaders = btoa(encodeURI(headerString));

        return encodedHeaders + '.' + btoa(encodeURI(this.payload)) + '.' + this.signature;
    }
}