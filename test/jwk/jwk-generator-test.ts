import {SigningAlgorithms} from "@lib/jwa";
import * as assert from "assert";
import {JwsBuilder} from "@lib/jws/jws-builder";
import {JwsValidator} from "@lib/validation/jws-validator";
import JWKGenerator from "@lib/jwk/generator/jwk-generator";

describe("JWK Generation", () => {

    it("SHA256 octet keys are supported", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.HS256,
            kid: 'secret'
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it("SHA384 octet keys are supported", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.HS384,
            kid: 'secret'
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it("SHA512 octet keys are supported", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.HS512,
            kid: 'secret'
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it("RSA256 keys are supported", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.RS256,
            kid: 'secret',
            key_ops: ['sign']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it("RSA384 keys are supported", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.RS384,
            kid: 'secret',
            key_ops: ['sign']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it("RSA512 keys are supported", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.RS512,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it("Keys for verification will not have private params", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.RS512,
            kid: 'secret',
            key_ops: ['verify']
        });

        const key = generator.generate();

        const {d, p, q, dp, dq, qi} = key;

        assert.equal(d, null);
        assert.equal(p, null);
        assert.equal(q, null);
        assert.equal(dp, null);
        assert.equal(dq, null);
        assert.equal(qi, null);
    });

    it("JWS octet objects signed with JWKs vended from the generator can be verified", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.HS256,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        const jwk = generator.generate();

        const builder = new JwsBuilder();
        const jws = builder
            .withJWK(jwk)
            .withPayload({
                foo: "bar"
            })
            .withHeaders({
                alg: SigningAlgorithms.HS256
            })
            .withProtectedHeaders({
                alg: SigningAlgorithms.HS256
            })
            .build();

        const validationResult = new JwsValidator(jws, jwk).validate();

        assert.equal(validationResult, true);
    });

    it("It generates EC256 keys", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.ES256,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it("It generates EC384 keys", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.ES384,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it("It generates EC512 keys", () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.ES512,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    it('generates keys that can correct validate signed tokens', () => {
        const generator = new JWKGenerator({
            alg: SigningAlgorithms.ES256,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        const jwk = generator.generate();

        const builder = new JwsBuilder();
        const jws = builder
            .withJWK(jwk)
            .withPayload({
                foo: "bar"
            })
            .withHeaders({
                alg: SigningAlgorithms.ES256
            })
            .withProtectedHeaders({
                alg: SigningAlgorithms.ES256
            })
            .build();

        assert.equal(new JwsValidator(jws, jwk).validate(), true);

    });
});