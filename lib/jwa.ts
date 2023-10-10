/**
 * JSON Web Algorithms: cryptographic algorithms and identifiers to be used with the JSON Web Signature (JWS),
 * JSON Web Encryption (JWE), and JSON Web Key (JWK) specifications
 * RFC Spec: https://datatracker.ietf.org/doc/html/rfc7518
 *
 * Implements supported algorithms using the Crypto node module
 *
 * The  algorithms in the crypto module are dependent on the available algorithms supported by the version of OpenSSL on the platform.
 * Examples are 'sha256', 'sha512', etc.
 * On recent releases of OpenSSL, openssl list -digest-algorithms will display the available digest algorithms.
 */

export enum SigningAlgorithms {
    // HMAC algorithms
    HS512 = 'HS512',
    HS384 = 'HS384',
    HS256 = 'HS256',

    // RSA Algorithms
    RS256 = 'RS256',
    RS384 = 'RS384',
    RS512 = 'RS512',

    // ECDSA
    ES256 = 'ES256',
    ES384 = 'ES384',
    ES512 = 'ES512',

    // RSASSA-PSS
    PS256 = 'PS256',
    PS384 = 'PS384',
    PS512 = 'PS512',
    none = 'none'
}

/**
 * These header values for alg are intended to be used for encryption as per: https://datatracker.ietf.org/doc/html/rfc7518#section-4.1
 */
export enum EncryptionAlgorithms {
    RSA1_5 = 'RSA1_5',
    'RSA-OAEP' = 'RSA-OAEP',
    'RSA-OAEP-256' = 'RSA-OAEP-256',
    A128KW = 'A128KW',
    A192KW = 'A192KW',
    A256KW = 'A256KW',
    dir = 'dir',
    'ECDH-ES' = 'ECDH-ES',
    'ECDH-ES+A128KW' = 'ECDH-ES+A128KW',
    'ECDH-ES+A192KW' = 'ECDH-ES+A192KW',
    'ECDH-ES+A256KW' = 'ECDH-ES+A256KW',
    'A128GCMKW' = 'A128GCMKW',
    'A192GCMKW' = 'A192GCMKW',
    'A256GCMKW' = 'A256GCMKW',
    'PBES2-HS256+A128KW' = 'PBES2-HS256+A128KW',
    'PBES2-HS384+A192KW' = 'PBES2-HS384+A192KW',
    'PBES2-HS512+A256KW' = 'PBES2-HS512+A256KW',
}

export const ECDSADigests : Record<string, string> = {
    'ES256': 'sha256',
    'ES384': 'sha384',
    'ES512': 'sha512'
};

export const getAlgorithm = (algorithm?: string) : SigningAlgorithms => {
    switch(algorithm) {
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
        default: throw new Error(`unrecognized alg: ${algorithm}`);
    }
};

