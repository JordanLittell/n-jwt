import {describe, test} from "node:test";
import {HMACSigner} from "../../lib/signing/hmac-signer";
import {Signer} from "../../lib/signing/signer";
import {Algorithm} from "../../lib/jwa";
import {JWK} from "../../lib/jwk/jwk";
import {JWKParser} from "../../lib/jwk/jwk-parser";
import * as assert from "assert";

describe("HMAC signing", () => {

    const signingInput = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    const jwk: JWK = new JWKParser().parse(`{
            "kty":"oct",
            "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        }`)

    test("supports sha256", () => {
        const signer: Signer = new HMACSigner(Algorithm.HS256);
        assert.doesNotThrow(() => signer.sign(signingInput, jwk));
    });

    test("supports sha512", () => {
        const signer: Signer = new HMACSigner(Algorithm.HS512);
        assert.doesNotThrow(() => signer.sign(signingInput, jwk));
    });

    test("supports sha384", () => {
        const signer: Signer = new HMACSigner(Algorithm.HS384);
        assert.doesNotThrow(() => signer.sign(signingInput, jwk));
    });
})