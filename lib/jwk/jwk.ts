/**
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key
 * RFC: https://datatracker.ietf.org/doc/html/rfc7517
 */

import * as https from "https";
import {Algorithm} from "../jwa";
import {CryptoKeyParam} from "./crypto-key-params";

export const EC_KEY_TYPE = 'EC'
export const RSA_KEY_TYPE = 'RSA'
export const OCT_KEY_TYPE = 'oct'

export type KeyType = 'EC' | 'RSA' | 'oct'
export type Usage = 'sig' | 'enc' // sign or encrypt?

/**
 * Identifies what key is to be used for:
 *    o  "sign" (compute digital signature or MAC)
 *    o  "verify" (verify digital signature or MAC)
 *    o  "encrypt" (encrypt content)
 *    o  "decrypt" (decrypt content and validate decryption, if applicable)
 *    o  "wrapKey" (encrypt key)
 *    o  "unwrapKey" (decrypt key and validate decryption, if applicable)
 *    o  "deriveKey" (derive key)
 *    o  "deriveBits" (derive bits not to be used as a key)
 */
export type KeyOperation = 'sign' | 'verify' | 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey' | 'deriveKey' | 'deriveBits';

interface CommonKeyParameters {
    kty: KeyType,
    use?: Usage,
    key_ops?: Array<KeyOperation>,
    alg?: Algorithm,
    kid?: string,
    x5u?: string,
    x5c?: string,
    x5t?: string,
    x5t_S256?: string,
    key_params: CryptoKeyParam
}

export class JWK {
    use?: Usage; // should correspond with usage of cert if specified
    key_ops?: Array<KeyOperation>
    kid?: string;
    kty: KeyType;

    // cert options
    x509URL?: string;
    x509CertChain?: string;
    x509Thumbprint?: string;
    x509S256Thumbprint?: string;

    key_params: CryptoKeyParam;

    constructor(params: CommonKeyParameters) {
        this.kty = params.kty;
        this.use = params.use;
        this.key_ops = params.key_ops;
        this.kid = params.kid;

        this.x509URL = params.x5u;
        this.x509CertChain = params.x5c;
        this.x509Thumbprint = params.x5t;
        this.x509S256Thumbprint = params.x5t_S256;

        this.key_params = params.key_params;
    }
}

// export class JWKSet {
//
//     keys: Map<string, JWK>
//
//     static async fromURL(url: string) : Promise<Map<string, JWK>> {
//
//         const jwkPromise = new Promise((resolve, reject) => {
//             https.get(new URL(url), (res) => {
//                 if (res.statusCode !== 200) {
//                     res.resume();
//                     reject(`Did not get an OK from the server. Code: ${res.statusCode}`);
//                 }
//
//                 let data = '';
//
//                 res.on('data', (chunk) => {
//                     data += chunk;
//                 });
//
//                 res.on('close', () => {
//                     resolve(JSON.parse(data));
//                 });
//             });
//         });
//
//         const jwkResult = await jwkPromise;
//
//         const results = new Map<string, JWK>();
//
//         const keys: Array<JWK>  = jwkResult['keys'].forEach(json => {
//             const jwk = new JWK({
//                 kty: json['kty'],
//                 alg: json['alg'],
//                 key_ops: json['key_ops'],
//                 use: json['use']
//             });
//
//             results.set(json['kid'], jwk);
//         });
//
//         return results;
//     }
//
//     constructor(keys: Array<JWK>) {
//
//     }
// }

// The use of an Encrypted JWK, which is a JWE with the UTF-8 encoding of a JWK as its plaintext value,
// is recommended for this purpose.