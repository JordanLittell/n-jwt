import {NodeAlgorithmMappings} from "../../node-algorithm-mappings";
import {Algorithm} from "../../jwa";
import {createHash, randomBytes} from "crypto";

export default class SHAGenerator {

    private readonly alg: Algorithm;

    constructor(alg: Algorithm) {
        this.alg = alg;
    }

    generate() : string {
        const hash = createHash(NodeAlgorithmMappings[this.alg]);
        hash.update(this.getRandomKey());
        return hash.digest('base64url');
    }

    private getRandomKey() : Buffer {
        switch (this.alg) {
            case Algorithm.HS256:
                return randomBytes(32);
            case Algorithm.HS512:
                return randomBytes(64);
            case Algorithm.HS384:
                return randomBytes(48);

            default:
                throw new Error(`unsupported key size for algorithm ${this.alg}`);
        }
    }
}