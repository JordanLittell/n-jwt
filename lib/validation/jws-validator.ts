import {Algorithm, ECDSADigests, getAlgorithm} from "@lib/jwa";
import {base64URLEncode} from "@lib/encoding";
import {SignerFactory} from "@lib/signing/signer-factory";
import {JWS} from "@lib/jws/jws";
import {JWK} from "@lib/jwk/jwk";
import * as crypto from "crypto";
import {NodeAlgorithmMappings} from "@lib/node-algorithm-mappings";
import {constants} from "crypto";

export class JwsValidator {

    private jws: JWS;
    private readonly jwk: JWK;

    constructor(jws: JWS, jwk: JWK) {
        this.jws = jws;
        this.jwk = jwk;
    }

    validate() {
        const signingInput = `${base64URLEncode(this.jws.headers)}.${base64URLEncode(this.jws.payload)}`;

        const alg = this.jws.parsedHeaders.alg;

        switch(alg) {
            case Algorithm.HS256.toString():
            case Algorithm.HS384.toString():
            case Algorithm.HS512.toString(): {
                const signer = new SignerFactory(getAlgorithm(alg));

                const calculatedSig = signer.create().sign(signingInput, this.jwk);

                return (calculatedSig === this.jws.signature);
            }
            case Algorithm.RS256.toString():
            case Algorithm.RS384.toString():
            case Algorithm.RS512.toString(): {
                const publicKey = crypto.createPublicKey({
                    key: JSON.parse(this.jwk.serialize()),
                    format: 'jwk',
                    encoding: 'utf8'
                });

                const verify = crypto.createVerify(NodeAlgorithmMappings[getAlgorithm(alg)]);
                verify.update(signingInput);
                return verify.verify({key: publicKey, padding: constants.RSA_PKCS1_PADDING}, this.jws.signature, 'base64url');
            }
            case Algorithm.ES256.toString():
            case Algorithm.ES384.toString():
            case Algorithm.ES512.toString(): {
                const publicKey = crypto.createPublicKey({
                    key: JSON.parse(this.jwk.serialize()),
                    format: 'jwk',
                    encoding: 'utf8'
                });
                const verify = crypto.createVerify(ECDSADigests[alg]);
                verify.update(signingInput);
                return verify.verify(publicKey, this.jws.signature, 'base64url');
            }

            default: throw new Error(`Unsupported signing algorithm ${alg}!`);
        }

    }
}