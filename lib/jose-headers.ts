// Header values for JSON Object Signing and Encryption (JOSE)
// together, these header values determine how to sign, encrypt, and validate JSON payloads sent through a network.
export enum Header {
    alg = 'alg', // specified in jwa
    enc = 'enc',
    zip = 'zip',
    jku = 'jku', // (JWK Set URL) Header Parameter
    jwk = 'jwk',
    kid = 'kid',
    x5u = 'x5u',
    x5c = 'x5c',
    x5t = 'x5t',
    x5t_S256 = 'x5t_S256',
    typ = 'typ',
    cty = 'cty',
    crit = 'crit'
}