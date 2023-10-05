import {describe, test} from "node:test";
import JWKGenerator from "../../lib/jwk/jwk-generator";
import {Algorithm} from "../../lib/jwa";
import * as assert from "assert";
import {JwsBuilder} from "../../lib/jws/jws-builder";
import {JwsValidator} from "../../lib/validation/jws-validator";

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

    test("RSA keys are supported", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.RS256,
            kid: 'secret'
        });

        assert.doesNotThrow(() => generator.generate());
    });

    test("JWS octet objects signed with JWKs vended from the generator can be verified", () => {
        const generator = new JWKGenerator({
            alg: Algorithm.HS256,
            kid: 'secret'
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
});