/**
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key
 * RFC: https://datatracker.ietf.org/doc/html/rfc7517
 */
import {SigningAlgorithms} from "../jwa";
import {RSAPrime} from "./crypto-key-params";
import {JWKClient} from "@lib/jwk/JWKClient";
import {HttpClient} from "@lib/http-client";

export const EC_KEY_TYPE = 'EC';
export const RSA_KEY_TYPE = 'RSA';
export const OCT_KEY_TYPE = 'oct';

export type KeyType = 'EC' | 'RSA' | 'oct';
export type Usage = 'sig' | 'enc'; // sign or encrypt

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

type CryptoKeyParam = 'RSAPublic' | 'RSAPrivate' | 'ECPrivate' | 'ECPublic' | 'Octet';

interface CommonKeyParameters {
    kty: KeyType,
    use?: Usage,
    key_ops?: KeyOperation[],
    alg?: SigningAlgorithms,
    kid?: string,
    x5u?: string,
    x5c?: string,
    x5t?: string,
    x5t_S256?: string,

    // all crypto key params
    n?: string,
    e?: string,
    d?: string,
    p?: string,
    q?: string,
    dp?: string,
    dq?: string,
    qi?: string,
    oth?: RSAPrime[],
    crv?: string,
    x?: string,
    y?: string,
    k?: string,
}

export class JWK {
    use?: Usage; // should correspond with usage of cert if specified
    key_ops?: KeyOperation[];
    kid?: string;
    kty: KeyType;

    // cert options
    x509URL?: string;
    x509CertChain?: string;
    x509Thumbprint?: string;
    x509S256Thumbprint?: string;

    private static jwkClient: JWKClient;

    // parameters used for generating cryptographic keys:

    // RSAPublic
    n?: string;
    e?: string;

    // RSAPrivate
    d?: string;   // ESPublic will just have a d
    p?: string;
    q?: string;
    dp?: string;
    dq?: string;
    qi?: string;
    oth?: RSAPrime[];

    // EC Private
    crv?: string;
    x?: string;
    y?: string;

    // EC Public
    // * just has a "d" param (which is part of an RSAPrivate key already)

    // Octet
    k?: string;

    static async fromJKU(url: URL, kid: string) : Promise<JWK> {
        const jwk = await this.getJWKClient().fetch(url, kid);

        if(!jwk) throw new Error(`Could not find jwk with kid ${kid} from ${url}`);

        return jwk!;
    }

    static getJWKClient() : JWKClient {
        return this.jwkClient ? this.jwkClient : new HttpClient();
    }

    static setJWKClient(client: JWKClient) : void {
        this.jwkClient = client;
    }


    constructor(params: CommonKeyParameters) {
        this.kty = params.kty;
        this.use = params.use;
        this.key_ops = params.key_ops;
        this.kid = params.kid;

        this.x509URL = params.x5u;
        this.x509CertChain = params.x5c;
        this.x509Thumbprint = params.x5t;
        this.x509S256Thumbprint = params.x5t_S256;

        this.n = params.n;
        this.e = params.e;
        this.d = params.d;
        this.p = params.p;
        this.q = params.q;
        this.dp = params.dp;
        this.dq = params.dq;
        this.qi = params.qi;
        this.crv = params.crv;
        this.x = params.x;
        this.y = params.y;
        this.k = params.k;
        this.oth = params.oth;
    }

    getKeyType() : CryptoKeyParam {
        if(this.d && this.kty === 'RSA') return 'RSAPrivate';
        if(this.n && this.e && this.kty === 'RSA') return 'RSAPublic';

        if(this.crv && this.x && this.y && this.kty === 'EC') return 'ECPrivate';
        if(this.d && this.kty === 'EC') return 'ECPublic';

        if(this.k && this.kty === 'oct') return 'Octet';

        throw new Error(`Missing required crypto key parameters for JWK of type: ${this.kty}`);
    }

    serialize() : string {
        return JSON.stringify({
            kty: this.kty,
            use: this.use,
            key_ops: this.key_ops,
            kid: this.kid,
            x509URL: this.x509URL,
            x509CertChain: this.x509CertChain,
            x509Thumbprint: this.x509Thumbprint,
            x509S256Thumbprint: this.x509S256Thumbprint,
            // set crypto key params
            n: this.n,
            e: this.e,
            d: this.d,
            p: this.p,
            q: this.q,
            dp: this.dp,
            dq: this.dq,
            qi: this.qi,
            crv: this.crv,
            x: this.x,
            y: this.y,
            k: this.k,
            oth: this.oth
        });
    }
}