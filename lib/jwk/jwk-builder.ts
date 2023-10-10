import {ECPrivate, ECPublic, Octet, RSAPrime, RSAPrivate, RSAPublic} from "@lib/jwk/crypto-key-params";
import {SigningAlgorithms} from "@lib/jwa";
import {JWK, KeyOperation, KeyType, Usage} from "@lib/jwk/jwk";

export class JwkBuilder {

    private _keyParamsSet: boolean;
    private _kty?: KeyType;
    private _use?: Usage;
    private _key_ops?: KeyOperation[];
    private _alg?: SigningAlgorithms;
    private _kid?: string;
    private _x5u?: string;
    private _x5c?: string;
    private _x5t?: string;
    private _x5t_S256?: string;

    private n?: string;
    private e?: string;
    private d?: string;
    private p?: string;
    private q?: string;
    private dp?: string;
    private dq?: string;
    private qi?: string;
    private crv?: 'P-256' | 'P-384' | 'P-521';
    private x?: string;
    private y?: string;
    private k?: string;
    private oth?: RSAPrime[];

    constructor() {
        this._keyParamsSet = false;
    }

    build() : JWK {
        const kty: KeyType = this._kty!;

        return new JWK({
            alg: this._alg,
            key_ops: this._key_ops,
            kid: this._kid,
            kty: kty,
            use: this._use,
            x5c: this._x5c,
            x5t: this._x5t,
            x5t_S256: this._x5t_S256,
            x5u: this._x5u,
            // Crypto Key Params
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

    withKty(value: KeyType) : JwkBuilder {
        this._kty = value;
        return this;
    }

    withAlg(value?: SigningAlgorithms) : JwkBuilder {
        this._alg = value;
        return this;
    }

    withUse(value?: Usage): JwkBuilder {
        this._use = value;
        return this;
    }

    withKeyOps(value?: KeyOperation[]): JwkBuilder {
        this._key_ops = value;
        return this;
    }

    withKid(value?: string): JwkBuilder {
        this._kid = value;
        return this;
    }

    withX5u(value?: string) : JwkBuilder {
        this._x5u = value;
        return this;
    }

    withX5c(value?: string) : JwkBuilder{
        this._x5c = value;
        return this;
    }

    withX5t(value?: string) : JwkBuilder {
        this._x5t = value;
        return this;
    }

    withX5tS256(value?: string) : JwkBuilder {
        this._x5t_S256 = value;
        return this;
    }

    withRSAPrivateParams(params: RSAPrivate) : JwkBuilder{
        this.d = params.d;
        this.dp = params.dp;
        this.dq = params.dq;
        this.qi = params.qi;
        this.q = params.q;
        this.e = params.e;
        this.n = params.n;
        this.p = params.p;
        this.oth = params.oth;
        return this;
    }

    withRSAPublicParams(params: RSAPublic): JwkBuilder {
        this.e = params.e;
        this.n = params.n;
        return this;
    }

    withECPublicParams(params: ECPublic): JwkBuilder {
        this.d = params.d;
        return this;
    }

    withECPrivateParams(params: ECPrivate): JwkBuilder {
        this.crv = params.crv;
        this.x = params.x;
        this.y = params.y;
        return this;
    }

    withOctetParams(params: Octet): JwkBuilder {
        this.k = params.k;
        return this;
    }

    private validate() {
        if (this._keyParamsSet) throw new Error(`
        A JWK can only support one key! 
        Make sure you are not setting multiple key params on the builder!`);

        this._keyParamsSet = true;
    }
}