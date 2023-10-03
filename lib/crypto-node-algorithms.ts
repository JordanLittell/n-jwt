export enum NodeAlgorithm {
    // HMAC algorithms
    HS512 = 'sha512',
    HS384 = 'sha384',
    HS256 = 'sha256',

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