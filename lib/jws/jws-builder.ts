import {JWK} from "@lib/jwk/jwk";
import {Header} from "@lib/jose-headers";
import {JWS} from "@lib/jws/jws";
import {base64URLEncode} from "@lib/encoding";
import {getAlgorithm} from "@lib/jwa";
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

        const signer : Signer = new SignerFactory(getAlgorithm(this.headers.alg)).create();

        return new JWS(
            JSON.stringify(this.headers),
            JSON.stringify(this.payload),
            signer.sign(message, this.jwk)
        );
    }
}