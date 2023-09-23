/**
 * These abstractions encapsulate the parameters that are fed into encryption algorithms
 * The use cases for the cryptographic keys can be encryption or signing
 * These parameters should be present in the JWK and should correspond to the kty
 */
export type CryptoKeyParam = RSAPublic | RSAPrivate | ECPrivate | ECPublic | Octet;
// TODO : make CryptoKey class with type (RSA), access level (public|private), and params {x,y,crv}

export interface RSAPrivate {
    d: string,
    p: string,
    q: string,
    dp: string,
    dq: string,
    qi: string,
    oth: Array<RSAPrime>,
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
    crv: string,
    x: string,
    y: string
}

export interface ECPublic {
    d: string,
}

export interface Octet {
    k: string;
}