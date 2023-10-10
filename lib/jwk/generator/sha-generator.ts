import {NodeAlgorithmMappings} from "@lib//node-algorithm-mappings";
import {SigningAlgorithms} from "@lib/jwa";
import {createHash, randomBytes} from "crypto";

export default class SHAGenerator {

    private readonly alg: SigningAlgorithms;

    constructor(alg: SigningAlgorithms) {
        this.alg = alg;
    }

    generate() : string {
        const hash = createHash(NodeAlgorithmMappings[this.alg]);
        hash.update(this.getRandomKey());
        return hash.digest('base64url');
    }

    private getRandomKey() : Buffer {
        switch (this.alg) {
            case SigningAlgorithms.HS256:
                return randomBytes(32);
            case SigningAlgorithms.HS512:
                return randomBytes(64);
            case SigningAlgorithms.HS384:
                return randomBytes(48);

            default:
                throw new Error(`unsupported key size for algorithm ${this.alg}`);
        }
    }
}