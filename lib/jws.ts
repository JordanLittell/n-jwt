/**
 * JSON Web Signature (JWS) represents content secured with digital signatures or Message Authentication Codes (MACs)
 * using JSON-based data structures.
 * RFC: https://datatracker.ietf.org/doc/html/rfc7515
 */
import {Header} from "./jose-headers";
import {base64URLDecode, base64URLEncode} from "./encoding";
import {Signer} from "./signing/signer";
import {HMACSigner} from "./signing/hmac-signer";
import {Algorithm} from "./jwa";
import {JWK} from "./jwk/jwk";

export class JWS {
    // Note that the payload can be any content and need not be a representation of a JSON object.
    payload: string;

    // we keep the raw header string for signature verification
    headers: string;
    signature: string;

    calculatedSignature: string;

    // parsedHeaders give structure to the headers to simplify business logic herein
    parsedHeaders: Partial<Record<Header, string>>;

    signer: Signer;

    jwk: JWK;

    static parse (token: string) : JWS {
        const [headers, payload, signature] = token.split('.').map((input) => base64URLDecode(input));
        return new JWS(headers, payload, signature);
    }

    constructor(headers: string, payload: string, signature: string) {
        this.payload = payload;
        this.headers = headers;
        this.signature = signature;

        const {x5t_S256 , alg , crit , cty , enc , jku , kid , typ , x5c , x5t , x5u , zip , jwk} = JSON.parse(headers);
        this.parsedHeaders = {x5t_S256 , alg , crit , cty , enc , jku , kid , typ , x5c , x5t , x5u , zip , jwk};
    }

    withJWK(jwk: JWK) {
        this.jwk = jwk;
    }

    /**
     * The JWS Compact
     *        Serialization of this result is BASE64URL(UTF8(JWS Protected
     *        Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS
     *        Signature)
     */
    serialize () : string {
        if(!this.jwk) throw new Error("JWK required to serialize token. Please set on instance via setJWK");

        const encodedHeaders = base64URLEncode(this.headers);
        const encodedPayload = base64URLEncode(this.payload);
        return encodedHeaders + '.' + encodedPayload + '.' + this.sign(this.jwk);
    }

    public sign (jwk: JWK): string {
        const signingInput = base64URLEncode(this.headers) + '.' +  base64URLEncode(this.payload);
        this.calculatedSignature = this.getSigner().sign(signingInput, jwk);
        return this.calculatedSignature;
    }

    private getSigner() : Signer {
        switch (this.parsedHeaders.alg) {
            case Algorithm.HS256:
            case Algorithm.HS384:
            case Algorithm.HS512:
                return new HMACSigner(this.parsedHeaders.alg)
        }

    }
}