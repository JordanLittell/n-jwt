import {getAlgorithm} from "../jwa";
import {base64URLEncode} from "../encoding";
import {SignerFactory} from "../signing/signer-factory";
import {JWS} from "../jws/jws";
import {JWK} from "../jwk/jwk";

export class JwsValidator {

    private jws: JWS;
    private readonly jwk: JWK;

    constructor(jws: JWS, jwk: JWK) {
        this.jws = jws;
        this.jwk = jwk;
    }

    validate() {
        const signer = new SignerFactory(getAlgorithm(this.jws.parsedHeaders.alg));
        const signingInput = `${base64URLEncode(this.jws.headers)}.${base64URLEncode(this.jws.payload)}`;
        const calculatedSig = signer.create().sign(signingInput, this.jwk);

        return (calculatedSig === this.jws.signature);
    }
}