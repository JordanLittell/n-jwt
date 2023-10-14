import {JWK} from "@lib/jwk/jwk";

/**
 * The intent of this interface is to abstract away the fetching of a key from a remote JWKSet
 * @url - the value of the jku JOSE header - a remote location of a published JWKSet
 * @kid - the id of the key in the JWKSet to look for
 */
export interface JWKClient {
    fetch(url: URL, kid: string) : Promise<JWK>;
}