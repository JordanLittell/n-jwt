import {JWK} from "../jwk/jwk";

/**
 * Uses a JWK to sign a payload
 */
export interface Signer {
    sign(message: string, key: JWK) : string;
}