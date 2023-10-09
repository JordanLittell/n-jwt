import {JWK} from "@lib/jwk/jwk";
import {Header} from "@lib/jose-headers";
import {JWS} from "@lib/jws/jws";
import {base64URLEncode} from "@lib/encoding";
import {Algorithm} from "@lib/jwa";
import {SignerFactory} from "@lib/signing/signer-factory";
import {Signer} from "@lib/signing/signer";

type JSONSerializableType = string | number | boolean | [] | object;
export class JwsBuilder {

    jwk: JWK;
    headers: Partial<Record<Header, string>>;
    protectedHeaders: Partial<Record<Header, string>>;
    payload: Record<string, JSONSerializableType>;

    public withHeaders(headers: Partial<Record<Header, string>>) {
        this.headers = headers;
        return this;
    }

    public withPayload(payload: Record<string, JSONSerializableType>) {
        this.payload = payload;
        return this;
    }

    public withProtectedHeaders(headers: Partial<Record<Header, string>>) {
        this.protectedHeaders = headers;
        return this;
    }

    public withJWK(jwk: JWK) {
        this.jwk = jwk;
        return this;
    }

    public build(): JWS {
        const message = `${base64URLEncode(JSON.stringify(this.protectedHeaders))}.${base64URLEncode(JSON.stringify(this.payload))}`;

        const signer : Signer = new SignerFactory(this.getAlgorithm()).create();

        return new JWS(
            JSON.stringify(this.headers),
            JSON.stringify(this.payload),
            signer.sign(message, this.jwk)
        );
    }

    private getAlgorithm() : Algorithm {
        switch(this.headers.alg) {
            case undefined: return Algorithm.none;
            case "HS512": return Algorithm.HS512;
            case "HS384": return Algorithm.HS384;
            case "HS256": return Algorithm.HS256;

            case "RS512": return Algorithm.RS512;
            case "RS384": return Algorithm.RS384;
            case "RS256": return Algorithm.RS256;

            case "ES512": return Algorithm.ES512;
            case "ES384": return Algorithm.ES384;
            case "ES256": return Algorithm.ES256;

            case "PS512": return Algorithm.PS512;
            case "PS384": return Algorithm.PS384;
            case "PS256": return Algorithm.PS256;
            default: throw new Error(`unrecognized alg: ${this.headers.alg}`);
        }
    }
}