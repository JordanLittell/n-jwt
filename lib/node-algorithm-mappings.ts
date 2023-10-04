/**
 * Converts the algorithm name encoded into the JWT such that the node crypto library recognizes it
 */
export const NodeAlgorithmMappings = {
    // HMAC algorithms
    HS512 : 'sha512',
    HS384: 'sha384',
    HS256: 'sha256',

    // RSA Algorithms
    RS256: 'RS256',
    RS384: 'RS384',
    RS512: 'RS512',

    // ECDSA
    ES256: 'ES256',
    ES384: 'ES384',
    ES512: 'ES512',

    // RSASSA-PSS
    PS256: 'PS256',
    PS384: 'PS384',
    PS512: 'PS512',
    none: 'none'
}