import {JWK, KeyOperation, Usage} from "../jwk";
import {Algorithm} from "../../jwa";
import {JwkBuilder} from "../jwk-builder";
import RSAGenerator from "./rsa-generator";
import SHAGenerator from "./sha-generator";

export interface JWKSpec {
    alg: Algorithm,
    use?: Usage,
    key_ops?: KeyOperation[],
    kid: string
}

export default class JWKGenerator {
    alg: Algorithm;
    use?: Usage;
    key_ops?: KeyOperation[];
    kid: string;

    constructor (spec: JWKSpec) {
        this.alg = spec.alg;
        this.use = spec.use;
        this.key_ops = spec.key_ops;
        this.kid = spec.kid;
    }

    public generate() : JWK {
        const jwk = new JwkBuilder();
        jwk
            .withAlg(this.alg)
            .withKid(this.kid)
            .withUse(this.use)
            .withKeyOps(this.key_ops);
        switch (this.alg) {
            case Algorithm.HS256:
            case Algorithm.HS512:
            case Algorithm.HS384: {
                jwk.withKty('oct');
                const k = new SHAGenerator(this.alg).generate();
                jwk.withOctetParams({ k });
                return jwk.build();
            }
            case Algorithm.RS256:
            case Algorithm.RS384:
            case Algorithm.RS512: {
                return new RSAGenerator(this.alg, this.key_ops).generate();
            }
            default:
                throw new Error(`Unsupported Algorithm ${this.alg}!`);
        }
    }
}