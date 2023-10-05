import {JWK, KeyOperation, Usage} from "./jwk";
import {Algorithm} from "../jwa";
import * as crypto from "crypto";
import {createHash} from "crypto";
import {NodeAlgorithmMappings} from "../node-algorithm-mappings";
import {JwkBuilder} from "./jwk-builder";
import {JWKParser} from "./jwk-parser";

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
                const hash = createHash(NodeAlgorithmMappings[this.alg]);
                hash.update(this.getRandomKey());
                jwk.withOctetParams({k: hash.digest('base64url')});
                return jwk.build();
            }
            case Algorithm.RS256:
            case Algorithm.RS384:
            case Algorithm.RS512: {
                const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
                    modulusLength: 2048,
                    publicExponent: 0x10001, // 65537
                });

                if(this.key_ops?.find((entry) => entry === 'verify')) {
                    const publicJWK = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
                    return new JWKParser().parse(JSON.stringify(publicJWK));
                }

                const privateJWK = privateKey.export({format: 'jwk'});
                return new JWKParser().parse(JSON.stringify(privateJWK));
            }
            default:
                throw new Error(`Unsupported Algorithm ${this.alg}!`);
        }
    }

    private getRandomKey() : Buffer {
        switch (this.alg) {
            case Algorithm.HS256:
                return crypto.randomBytes(32);
            case Algorithm.HS512:
                return crypto.randomBytes(64);
            case Algorithm.HS384:
                return crypto.randomBytes(48);

            default:
                throw new Error(`unsupported key size for algorithm ${this.alg}`);
        }

    }
}