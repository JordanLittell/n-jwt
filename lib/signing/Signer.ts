import {JWK} from "@lib/jwk/jwk";

/**
 * Uses a JWK to sign a payload
 */

export {};

export interface Signer {
    sign(message: string, key: JWK) : string;
}