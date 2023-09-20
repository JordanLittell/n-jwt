/**
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key
 * RFC: https://datatracker.ietf.org/doc/html/rfc7517
 */

import {Algorithm} from "./jwa";

export {}

type KeyType = 'EC' | 'RSA' | 'oct'
type Usage = 'sig' | 'enc'
type KeyOperation = 'sign' | 'verify' | 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey' | 'deriveKey' | 'deriveBits';

interface KeyParameters {
    kty: KeyType,
    use: Usage,
    key_ops: Array<KeyOperation>,
    alg: Algorithm,
    kid?: string,

    x5u?: string,
    x5c?: string,
    x5t?: string,
    x5t_S256?: string
}

export class JWK {
    type: KeyType;
    use: Usage; // should correspond with usage of cert if specified
    key_ops: Array<KeyOperation>

    // cert options
    x509URL: string;
    x509CertChain: string;
    x509Thumbprint: string;
    x509S256Thumbprint: string;

    constructor(params: KeyParameters) {

    }
}

export class JWKSet {

    keys: Array<JWK>

    constructor(keys: Array<JWK>) {
        this.keys = keys;
    }
}

// The use of an Encrypted JWK, which is a JWE with the UTF-8 encoding of a JWK as its plaintext value,
// is recommended for this purpose.