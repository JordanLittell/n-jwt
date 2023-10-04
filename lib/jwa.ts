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

export enum Algorithm {
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


export const getAlgorithm = (algorithm?: string) : Algorithm => {
    switch(algorithm) {
        case undefined: return Algorithm.none;
        case "HS512": return Algorithm.HS512
        case "HS384": return Algorithm.HS384
        case "HS256": return Algorithm.HS256

        case "RS512": return Algorithm.RS512
        case "RS384": return Algorithm.RS384
        case "RS256": return Algorithm.RS256

        case "ES512": return Algorithm.ES512
        case "ES384": return Algorithm.ES384
        case "ES256": return Algorithm.ES256

        case "PS512": return Algorithm.PS512
        case "PS384": return Algorithm.PS384
        case "PS256": return Algorithm.PS256
        default: throw new Error(`unrecognized alg: ${algorithm}`)
    }
}








