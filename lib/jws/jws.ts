/**
 * JSON Web Signature (JWS) represents content secured with digital signatures or Message Authentication Codes (MACs)
 * using JSON-based data structures.
 * RFC: https://datatracker.ietf.org/doc/html/rfc7515
 *
 * JWS can either be produced or consumed
 */
import {Header} from "@lib/jose-headers";
import {base64URLDecode, base64URLEncode} from "@lib/encoding";

export class JWS {
    // Note that the payload can be any content and need not be a representation of a JSON object.
    payload: string;

    // we keep the raw header string for signature verification
    headers: string;
    signature: string;

    // parsedHeaders give structure to the headers to simplify business logic herein
    parsedHeaders: Partial<Record<Header, string>>;

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

    /**
     * The JWS Compact
     *        Serialization of this result is BASE64URL(UTF8(JWS Protected
     *        Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS
     *        Signature)
     */
    serialize () : string {
        const encodedHeaders = base64URLEncode(this.headers);
        const encodedPayload = base64URLEncode(this.payload);
        const encodedSignature = base64URLEncode(this.signature);

        return `${encodedHeaders}.${encodedPayload}.${encodedSignature}`;
    }
}