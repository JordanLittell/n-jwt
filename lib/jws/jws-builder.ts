import {JWK} from "@lib/jwk/jwk";
import {Header} from "@lib/jose-headers";
import {JWS} from "@lib/jws/jws";
import {base64URLEncode} from "@lib/encoding";
import {SigningAlgorithms} from "@lib/jwa";
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

    private getAlgorithm() : SigningAlgorithms {
        switch(this.headers.alg) {
            case undefined: return SigningAlgorithms.none;
            case "HS512": return SigningAlgorithms.HS512;
            case "HS384": return SigningAlgorithms.HS384;
            case "HS256": return SigningAlgorithms.HS256;

            case "RS512": return SigningAlgorithms.RS512;
            case "RS384": return SigningAlgorithms.RS384;
            case "RS256": return SigningAlgorithms.RS256;

            case "ES512": return SigningAlgorithms.ES512;
            case "ES384": return SigningAlgorithms.ES384;
            case "ES256": return SigningAlgorithms.ES256;

            case "PS512": return SigningAlgorithms.PS512;
            case "PS384": return SigningAlgorithms.PS384;
            case "PS256": return SigningAlgorithms.PS256;
            default: throw new Error(`unrecognized alg: ${this.headers.alg}`);
        }
    }
}