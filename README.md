# Node JWT (n-jwt)
[![CircleCI](https://dl.circleci.com/status-badge/img/circleci/QpYzT8jWrMkgEPvicwJuap/YNYnTVcP4HB47YfXPRmTX/tree/main.svg?style=svg&circle-token=cc1487f8c09dcc26fa3b7be11dadfeb157362edf)](https://dl.circleci.com/status-badge/redirect/circleci/QpYzT8jWrMkgEPvicwJuap/YNYnTVcP4HB47YfXPRmTX/tree/main) [![cov](https://JordanLittell.github.io/n-jwt/badges/coverage.svg?)](https://github.com/JordanLittell/n-jwt/actions)

Produce and consume JSON objects secured with industry-standard encryption and signing algorithms.

## Use Cases

### JWK

There are classes for both producing and conusming JWKs

#### JWK Generation (Producing)
Currently this package supports generating (both public and private) encryption keys for several algorithms.

Here is an example of generating an RSA Public JWK:
```
const generator = new JWKGenerator({
    alg: Algorithm.RS512,
    kid: 'secret',
    key_ops: ['sign', 'verify']
});
```

At the moment, only RSA, SHA, and ECDSA algorithms are supported (currently there is no support for RSASSA-PSS).

#### JWK Parsing (Consuming)
Consuming JWK objects over the wire can be done by using the built-in JWKParser class like so:

Here is an example of generating an RSA Public JWK:
```
const key = `{
    "kty":"EC",
    "crv":"P-256",
    "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
}`;

const jwk : JWK = parser.parse(key);
```

At the moment, only RSA, SHA, and ECDSA algorithms are supported (currently there is no support for RSASSA-PSS).

### JWS
#### Producing JWS
To create JWS JSON objects, you can use the builder like so:
```
const builder = new JwsBuilder();
const jws = builder
    .withHeaders({alg: "RS256"})
    .withProtectedHeaders({alg: "RS256"})
    .withJWK(jwk)
    .withPayload({"iss":"joe",  "exp": 1300819380, "http://example.com/is_root": true})
    .build();

console.log(jws.serialize());
```

#### Consuming JWS
To consume a JWS object from an external source, use the parser on the JWS class like so:

```
const token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AF9JZKWRn2omJDrJrWeoVQyjR3PcGFiAe0_dC04hwyE";
const jws = JWS.parse(token);
```

#### JWS Validation
To validate the signatures on the JWS tokens, use the JWSValidator. Note that the signatures on JWS tokens should be validated with JWKs. As such, the validator expects both the JWS and JWK as constructor parameters:

```
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

const validator = new JwsValidator(jws, jwk);
validator.validate();
```

Currently only RSA and HS algorithms are supported. 

### JWE
Under development



