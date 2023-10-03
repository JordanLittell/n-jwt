import * as crypto from "crypto";
import {NodeAlgorithm} from "../jwa";
import {base64URLDecode} from "../encoding";

export class JwsValidator {

    readonly signature: string;
    readonly headers: string;
    readonly payload: string;


    constructor(token: string) {
        const [headers, payload, signature] = token.split('.');
        this.signature = signature;
        this.payload = payload;
        this.headers = headers;
    }

    validate(key: string) {
        const signingInput = `${this.headers}.${this.payload}`;

        const hmac = crypto.createHmac('sha256', key)
        hmac.update(signingInput)
        const computedSignature = hmac.digest()

        const tokenSignature = Buffer.from(base64URLDecode(this.signature));

        return computedSignature.toString('base64url') == tokenSignature.toString('base64url');
    }
}