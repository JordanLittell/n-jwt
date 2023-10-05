import {CryptoKeyParam, ECPrivate, ECPublic, Octet, RSAPrivate, RSAPublic} from "./crypto-key-params";
import {Algorithm} from "../jwa";
import {JWK, KeyOperation, KeyType, Usage} from "./jwk";

export class JwkBuilder {

    private _keyParamsSet: boolean;
    private _kty?: KeyType;
    private _use?: Usage;
    private _key_ops?: KeyOperation[];
    private _alg?: Algorithm;
    private _kid?: string;
    private _x5u?: string;
    private _x5c?: string;
    private _x5t?: string;
    private _x5t_S256?: string;
    private _key_params?: CryptoKeyParam;

    constructor() {
        this._keyParamsSet = false;
    }

    build() : JWK {
        const kty: KeyType = this._kty!;
        const keyParams: CryptoKeyParam = this._key_params!;

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
            key_params: keyParams
        });
    }

    withKeyParamsSet(value: boolean) : JwkBuilder {
        this._keyParamsSet = value;
        return this;
    }

    withKty(value: KeyType) : JwkBuilder {
        this._kty = value;
        return this;
    }

    withAlg(value?: Algorithm) : JwkBuilder {
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
        this.validate();
        this._key_params = params;
        return this;
    }

    withRSAPublicParams(params: RSAPublic): JwkBuilder {
        this.validate();
        this._key_params = params;
        return this;
    }

    withECPublicParams(params: ECPublic): JwkBuilder {
        this.validate();
        this._key_params = params;
        return this;
    }

    withECPrivateParams(params: ECPrivate): JwkBuilder {
        this.validate();
        this._key_params = params;
        return this;
    }

    withOctetParams(params: Octet): JwkBuilder {
        this.validate();
        this._key_params = params;
        return this;
    }

    private validate() {
        if (this._keyParamsSet) throw new Error(`
        A JWK can only support one key! 
        Make sure you are not setting multiple key params on the builder!`);

        this._keyParamsSet = true;
    }
}