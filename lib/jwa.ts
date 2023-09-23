/**
 * JSON Web Algorithms: cryptographic algorithms and identifiers to be used with the JSON Web Signature (JWS),
 * JSON Web Encryption (JWE), and JSON Web Key (JWK) specifications
 * RFC Spec: https://datatracker.ietf.org/doc/html/rfc7518
 *
 * Impelements supported algorithms using the Crypto node module
 *
 * The  algorithms in the crypto module are dependent on the available algorithms supported by the version of OpenSSL on the platform.
 * Examples are 'sha256', 'sha512', etc.
 * On recent releases of OpenSSL, openssl list -digest-algorithms will display the available digest algorithms.
 */

export enum Algorithm {
    // HMAC algorithms
    HS512 = 'HS512',
    HS38 = 'HS384',
    HS25 = 'HS256',

    // RSA Algorithms
    RS25 = 'RS256',
    RS38 = 'RS384',
    RS51 = 'RS512',

    // ECDSA
    ES25 = 'ES256',
    ES38 = 'ES384',
    ES51 = 'ES512',

    // RSASSA-PSS
    PS25 = 'PS256',
    PS38 = 'PS384',
    PS51 = 'PS512',
    none = 'none'
}








