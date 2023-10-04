/**
 * These abstractions encapsulate the parameters that are fed into encryption algorithms
 * The use cases for the cryptographic keys can be encryption or signing
 * These parameters should be present in the JWK and should correspond to the kty
 */
export type CryptoKeyParam = RSAPublic | RSAPrivate | ECPrivate | ECPublic | Octet;
export const isRSAPublic = (key: CryptoKeyParam): key is RSAPublic => {
    return (key as RSAPublic).kind === "RSAPublic";
}

export const isOctet = (key: CryptoKeyParam): key is Octet => {
    return (key as Octet).kind === "Octet";
}

export interface RSAPrivate {
    d: string,
    p: string,
    q: string,
    dp: string,
    dq: string,
    qi: string,
    oth: Array<RSAPrime>,
    kind: string
}

export interface RSAPrime {
    r: string,
    d: string,
    t: string,
    kind: string
}

export interface RSAPublic {
    n: string,
    e: string,
    kind: string
}

export interface ECPrivate {
    crv: string,
    x: string,
    y: string,
    kind: string
}

export interface ECPublic {
    d: string,
    kind: string
}

export interface Octet {
    k: string,
    kind: string
}