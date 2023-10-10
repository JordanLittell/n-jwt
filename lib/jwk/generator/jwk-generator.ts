import {JWK, KeyOperation, Usage} from "../jwk";
import {SigningAlgorithms} from "@lib/jwa";
import {JwkBuilder} from "@lib/jwk/jwk-builder";
import RSAGenerator from "@lib/jwk/generator/rsa-generator";
import SHAGenerator from "@lib/jwk/generator/sha-generator";
import ECGenerator from "@lib/jwk/generator/ec-generator";

export interface JWKSpec {
    alg: SigningAlgorithms,
    use?: Usage,
    key_ops?: KeyOperation[],
    kid: string
}

export default class JWKGenerator {
    alg: SigningAlgorithms;
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
            case SigningAlgorithms.HS256:
            case SigningAlgorithms.HS512:
            case SigningAlgorithms.HS384: {
                jwk.withKty('oct');
                const k = new SHAGenerator(this.alg).generate();
                jwk.withOctetParams({ k });
                return jwk.build();
            }
            case SigningAlgorithms.RS256:
            case SigningAlgorithms.RS384:
            case SigningAlgorithms.RS512: {
                return new RSAGenerator(this.alg, this.key_ops).generate();
            }
            case SigningAlgorithms.ES256:
            case SigningAlgorithms.ES384:
            case SigningAlgorithms.ES512: {
                return new ECGenerator(this.alg, this.key_ops).generate();
            }
            default:
                throw new Error(`Unsupported Algorithm ${this.alg}!`);
        }
    }
}