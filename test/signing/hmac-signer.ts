import {HMACSigner} from "@lib/signing/hmac-signer";
import {Signer} from "../../lib/signing/signer";
import {SigningAlgorithms} from "@lib/jwa";
import {JWK} from "@lib/jwk/jwk";
import {JWKParser} from "@lib/jwk/jwk-parser";
import * as assert from "assert";
import {JWS} from "@lib/jws/jws";
import {JwsValidator} from "@lib/validation/jws-validator";

describe("HMAC signing", () => {

    const signingInput = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    const jwk: JWK = new JWKParser().parse(`{
            "kty":"oct",
            "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        }`);

    it("supports sha256", () => {
        const signer: Signer = new HMACSigner(SigningAlgorithms.HS256);
        assert.doesNotThrow(() => signer.sign(signingInput, jwk));
    });


    it("It parses tokens from other libraries", () => {
        // token taken from https://github.com/michaelrhanson/jwt-js/blob/master/tests/jsonWebTokenTest.htm
        const token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AF9JZKWRn2omJDrJrWeoVQyjR3PcGFiAe0_dC04hwyE";
        const jwk: JWK = new JWKParser().parse(`{
            "kty":"oct",
            "k":"hmackey"
        }`);

        const jws = JWS.fromToken(token);
        new JwsValidator(jws, jwk);
    });

    it("supports sha512", () => {
        const signer: Signer = new HMACSigner(SigningAlgorithms.HS512);
        assert.doesNotThrow(() => signer.sign(signingInput, jwk));
    });

    it("supports sha384", () => {
        const signer: Signer = new HMACSigner(SigningAlgorithms.HS384);
        assert.doesNotThrow(() => signer.sign(signingInput, jwk));
    });
});