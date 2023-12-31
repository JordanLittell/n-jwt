import {JWK, KeyOperation} from "../jwk";
import {JWKParser} from "../jwk-parser";
import * as crypto from "crypto";
import {SigningAlgorithms} from "@lib/jwa";

export default class ECGenerator {

    private readonly alg : SigningAlgorithms;
    private readonly keyOps? : KeyOperation[];

    constructor (alg: SigningAlgorithms, keyOps?: KeyOperation[]) {
        this.alg = alg;
        this.keyOps = keyOps;
    }
    generate() : JWK {

        if(!this.keyOps)
            throw new Error("With RSA keys, you must indicate the use in keyOps: 'sign', 'verify', or both");

        // Generate ECDSA key pair
        const { privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: this.getNamedCurve()
        });

        if(this.keyOps?.find((entry) => entry === 'sign')) {
            const privateJWK = privateKey.export({format: 'jwk'});

            return new JWKParser().parse(JSON.stringify({...privateJWK, kty: 'EC'}));
        }
        const publicJWK = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
        return new JWKParser().parse(JSON.stringify({...publicJWK, kty: 'EC'}));
    }

    /**
     * Values here taken from: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
     *
     * @private name of the curve parameter
     */
    private getNamedCurve() : string {
        switch (this.alg) {
            case SigningAlgorithms.ES256:
                return 'P-256';
            case SigningAlgorithms.ES384:
                return 'P-384';
            case SigningAlgorithms.ES512:
                return 'P-521';
            default:
                throw new Error(`unsupported algorithm ${this.alg}`);
        }
    }
}