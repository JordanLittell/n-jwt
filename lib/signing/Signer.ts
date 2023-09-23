import {JWK} from "../jwk/jwk";

/**
 * Uses a JWK to sign a payload
 */
export default class Signer {

    constructor(jwk: JWK) {
        jwk.key_params;
    }

    sign (message: string) : string {
        return ""
    }

    private getSigningKey(): string {
        return "";
    }
}