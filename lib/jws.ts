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
import {JWK} from "./jwk/jwk";
import {JWKParser} from "./jwk/jwk-parser";
import {Octet} from "./jwk/crypto-key-params";

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
        this.headers = headers;
    }

    isValid () : boolean {
        return true
    }

    serialize () : string {
        const headerString = JSON.stringify(this.headers);
        const encodedHeaders = btoa(encodeURI(headerString));
        return encodedHeaders + '.' + btoa(encodeURI(this.payload)) + '.' + this.signature;
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
    private sign() : string {
        const keyId = this.headers.kid;
        const jwkURL = this.headers.jku;
        const jwkPayload = this.headers.jwk;

        let jwk: JWK;

        const parser : JWKParser = new JWKParser();

        if(jwkPayload) {
            jwk = parser.parse(jwkPayload)
            if(jwk.kid != keyId) throw new Error(`The jwk has invalid kid. Expected ${keyId} but has ${jwk.kid}`)
        }

        // switch (this.headers.alg) {
        //     case(Algorithm.HS512.valueOf()):
        //     const {k} : Octet = jwk.key_params;
        //     const hmac = crypto.createHmac('sha512', )
        //     hmac.digest('hex')
        // }

        return '';
    }
}