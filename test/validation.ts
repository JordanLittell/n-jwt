import {JwsValidator} from "@lib/validation/jws-validator";
import {JWK} from "@lib/jwk/jwk";
import {JWKParser} from "@lib/jwk/jwk-parser";
import {JwsBuilder} from "@lib/jws/jws-builder";
import * as assert from "assert";
import {JWS} from "@lib/jws/jws";

describe("validating tokens using HMAC signatures", () => {

    const validToken = {
        headers: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9",
        payload: "eyJpc3MiOiJqb2UiLCJleHAiOiIxMzAwODE5MzgwIn0",
        signature: "U3NjSl9zZFVUaEhlOFEwU2pUOEdPdEt2bGMteWxjejZ1V1BmWURyUGVFcUpvc2pmQVdldmwxWUg4dHh0S2FObkNBR1lub08zM2d4aHRqZFVZenRGbmc"
    };

   it("validator returns true when signature is valid", () => {
       const jwkStr = `{
        "kty":"oct",
        "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
     }`;
       const jwk: JWK = (new JWKParser()).parse(jwkStr);

       const jws: JWS = JWS.fromToken(`${validToken.headers}.${validToken.payload}.${validToken.signature}`);

       const validator = new JwsValidator(jws, jwk);
       assert.equal(validator.validate(), true);
   });

    it("validator returns false when signature is not valid", () => {
        const headers = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9";
        const payload = "eyJpc3MiOiJqb2UiLCJleHAiOiIxMzAwODE5MzgwIn0";
        const sig = "INVALID!!!___U3NjSl9zZFVUaEhlOFEwU2pUOEdPdEt2bGMteWxjejZ1V";

        const jwkStr = `{
            "kty":"oct",
            "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        }`;
        const jwk: JWK = (new JWKParser()).parse(jwkStr);

        const jws: JWS = JWS.fromToken(`${headers}.${payload}.${sig}`);

        const validator = new JwsValidator(jws, jwk);
        assert.equal(validator.validate(), false);
    });

    it("validator returns false when key is invalid", () => {
        const jwkStr = `{
        "kty":"oct",
        "k":"invalid"
     }`;
        const jwk: JWK = (new JWKParser()).parse(jwkStr);

        const jws: JWS = JWS.fromToken(`${validToken.headers}.${validToken.payload}.${validToken.signature}`);

        const validator = new JwsValidator(jws, jwk);
        assert.equal(validator.validate(), false);
    });

    it("validator returns false when the token has been tampered", () => {
        const jwkStr = `{
            "kty":"oct",
            "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        }`;
        const jwk: JWK = (new JWKParser()).parse(jwkStr);

        const builder = new JwsBuilder();

        const attackerJWS = builder
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
                tampered: "true"
            })
            .withJWK(jwk)
            .build();

        const tamperedPayload = attackerJWS.serialize().split('.')[1];
        const tamperedToken = `${validToken.headers}.${tamperedPayload}.${validToken.signature}`;
        const tamperedJWS = JWS.fromToken(tamperedToken);


        const validator = new JwsValidator(tamperedJWS, jwk);
        assert.equal(validator.validate(), false);
    });
});