import {JWS} from "@lib/jws/jws";
import * as assert from "assert";
import {JWKParser} from "@lib/jwk/jwk-parser";
import {JwsBuilder} from "@lib/jws/jws-builder";
import {JWK} from "@lib/jwk/jwk";
import {JwsValidator} from "@lib/validation/jws-validator";

it("parsing works", () => {
    const token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert.doesNotThrow(() => JWS.fromToken(token));
});

it("parsing and serializing do not modify the token", () => {

    const jwkStr = `{
        "kty":"oct",
        "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
     }`;
    const jwk: JWK = (new JWKParser()).parse(jwkStr);

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

    const parsedJWS = JWS.fromToken(jws.serialize());

    assert.equal(parsedJWS.serialize(), jws.serialize());
});

describe('hashing algorithms', () => {

    it("sha256 is supported", () => {

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


    it("RSA256 is supported", () => {

        const jwkStr = `{"kty":"RSA",
          "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
          "e":"AQAB",
          "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
          "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
          "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
          "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
          "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
          "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
         }`;
        const jwk = new JWKParser().parse(jwkStr);

        const builder = new JwsBuilder();
        const jws = builder
            .withHeaders({alg: "RS256"})
            .withProtectedHeaders({alg: "RS256"})
            .withJWK(jwk)
            .withPayload({"iss":"joe",  "exp": 1300819380, "http://example.com/is_root": true})
            .build();

        assert.doesNotThrow(() => jws.serialize());
        assert.equal(new JwsValidator(jws, jwk).validate(), true);
    });

    it("throws on an unrecognized alg", () => {
        const builder = new JwsBuilder()
            .withHeaders({alg: "blah"})
            .withProtectedHeaders({alg: "blah"})
            .withPayload({"iss":"joe",  "exp": 1300819380, "http://example.com/is_root": true});

        assert.throws(() => builder.build());
    });
});