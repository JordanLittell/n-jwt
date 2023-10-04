import {describe, test} from "node:test";
import {JWS} from "../../lib/jws/jws";
import * as assert from "assert";
import {JWKParser} from "../../lib/jwk/jwk-parser";
import {JwsBuilder} from "../../lib/jws/jws-builder";
import {JWK} from "../../lib/jwk/jwk";

test("parsing works", () => {
    const token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert.doesNotThrow(() => JWS.parse(token));
})

test("parsing and serializing do not modify the token", () => {

    const jwkStr = `{
        "kty":"oct",
        "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
     }`
    const jwk: JWK = (new JWKParser()).parse(jwkStr)

    const builder = new JwsBuilder();

    const jws = builder
        .withHeaders({
            typ: "JWT",
            alg: "HS512"
        })
        .withProtectedHeaders({
            typ: "JWT",
            alg: "HS512"
        })
        .withPayload({
            iss: "joe",
            exp: "1300819380",
        })
        .withJWK(jwk)
        .build();

    const parsedJWS = JWS.parse(jws.serialize());

    assert.equal(parsedJWS.serialize(), jws.serialize());
})

describe('hashing algorithms', () => {

    test("sha256 is supported", () => {

        const headers = `{ "typ":"JWT",
                "alg":"HS256"
            }
        `;
        const payload = `{
            "iss":"joe",
            "exp":1300819380,
            "http://example.com/is_root":true
        }`;

        const signature = `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`;
        const jws : JWS = new JWS(headers, payload, signature);

        jws.serialize();
    });
})