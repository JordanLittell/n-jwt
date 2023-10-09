import {describe, test} from "node:test";
import {Algorithm} from "@lib/jwa";
import * as assert from "assert";
import {JwsBuilder} from "@lib/jws/jws-builder";
import {JwsValidator} from "@lib/validation/jws-validator";
import JWKGenerator from "@lib/jwk/generator/jwk-generator";

describe("JWK Generation", () => {

    test("SHA256 octet keys are supported", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.HS256,
            kid: 'secret'
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("SHA384 octet keys are supported", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.HS384,
            kid: 'secret'
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("SHA512 octet keys are supported", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.HS512,
            kid: 'secret'
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("RSA256 keys are supported", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.RS256,
            kid: 'secret',
            key_ops: ['sign']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("RSA384 keys are supported", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.RS384,
            kid: 'secret',
            key_ops: ['sign']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("RSA512 keys are supported", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.RS512,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("Keys for verification will not have private params", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.RS512,
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

    test("JWS octet objects signed with JWKs vended from the generator can be verified", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.HS256,
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
                alg: Algorithm.HS256
            })
            .withProtectedHeaders({
                alg: Algorithm.HS256
            })
            .build();

        const validationResult = new JwsValidator(jws, jwk).validate();

        assert.equal(validationResult, true);
    });

    test("It generates EC256 keys", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.ES256,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("It generates EC384 keys", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.ES384,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("It generates EC512 keys", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.ES512,
            kid: 'secret',
            key_ops: ['sign', 'verify']
        });

        assert.doesNotThrow(() => generator.generate());
    });
});