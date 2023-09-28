/**
 * JSON Web Signature (JWS) represents content secured with digital signatures or Message Authentication Codes (MACs)
 * using JSON-based data structures.
 * RFC: https://datatracker.ietf.org/doc/html/rfc7515
 */
import {Algorithm, NodeAlgorithm} from "./jwa";
import * as crypto from "crypto";
import {Header} from "./jose";
import {JWK} from "./jwk/jwk";
import {JWKParser} from "./jwk/jwk-parser";
import {CryptoKeyParam, isOctet} from "./jwk/crypto-key-params";
import {toASCII} from "punycode";
import {base64URLEncode} from "./encoding";

export class JWS {
    // Note that the payload can be any content and need not be a representation of a JSON object.
    payload: string;
    headers: Partial<Record<Header, string>>;
    protectedHeaders: Partial<Record<Header, string>>;

    constructor(headers: Partial<Record<Header, string>>, payload: string) {
        this.payload = payload;
        this.headers = headers;
        const {typ, alg} = this.headers
        this.protectedHeaders = {typ, alg};
    }

    isValid () : boolean {
        return true
    }

    /**
     * The JWS Compact
     *        Serialization of this result is BASE64URL(UTF8(JWS Protected
     *        Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS
     *        Signature)
     */
    serialize () : string {
        console.log(JSON.stringify(this.protectedHeaders));
        const encodedHeaders = base64URLEncode(JSON.stringify(this.protectedHeaders));
        const encodedPayload = base64URLEncode(this.payload);
        return encodedHeaders + '.' + encodedPayload + '.' + this.getSignature();
    }

    static parse (token: string) : JWS {
        return new JWS({x5t_S256: "", alg: "", crit: "", cty: "", enc: "", jku: "", kid: "", typ: "", x5c: "", x5t: "", x5u: "", zip: "", jwk: ''}, '');
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
    private getSignature() : string {
        const keyId = this.headers.kid;
        const jwkURL = this.headers.jku;
        const jwkPayload = this.headers.jwk;

        let jwk: JWK;

        const parser : JWKParser = new JWKParser();

        const jwkInput : string = jwkPayload ? jwkPayload : "";

        jwk = parser.parse(jwkInput)
        if(jwk.kid != keyId) throw new Error(`The jwk has invalid kid. Expected ${keyId} but has ${jwk.kid}`)

        const signingInput = toASCII(base64URLEncode(JSON.stringify(this.protectedHeaders))) + '.' +  base64URLEncode(this.payload);
        const keyParams : CryptoKeyParam =  jwk.key_params

        switch (this.headers.alg) {
            // type narrowing
            case(Algorithm.HS512.valueOf()):
                if(isOctet(keyParams)) {
                    const {k} = keyParams;
                    const hmac = crypto.createHmac(NodeAlgorithm.HS512, k)
                    hmac.update(signingInput)
                    return hmac.digest('base64url')
                }
                return ''
        }

        return '';
    }
}