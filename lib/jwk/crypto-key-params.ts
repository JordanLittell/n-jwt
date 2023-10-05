/**
 * These abstractions encapsulate the parameters that are fed into encryption algorithms
 * The use cases for the cryptographic keys can be encryption or signing
 * These parameters should be present in the JWK and should correspond to the kty
 */
export interface RSAPrivate {
    n: string,
    e: string,
    d: string,
    p: string,
    q: string,
    dp: string,
    dq: string,
    qi: string,
    oth: RSAPrime[],
}

export interface RSAPrime {
    r: string,
    d: string,
    t: string
}

export interface RSAPublic {
    n: string,
    e: string
}

export interface ECPrivate {
    crv: 'P-256' | 'P-384' | 'P-521',
    x: string,
    y: string
}

export interface ECPublic {
    d: string
}

export interface Octet {
    k: string
}