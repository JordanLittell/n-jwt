import {describe, test} from "node:test";
import {JWS} from "../lib/jws";
import {Algorithm} from "../lib/jwa";
import * as assert from "assert";

describe("Serializing JWS tokens", () => {
    const payload : string = '{"iss":"joe",\r\n' +
        ' "exp":1300819380,\r\n' +
        ' "http://example.com/is_root":true}';

    describe("using HMAC", () => {
        const jwk : string = `{"kty":"oct", "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`;

        const jws = new JWS({typ: "JWT", alg: Algorithm.HS512, jwk: jwk}, payload);
        const output = jws.serialize();

        test("it serializes the token appropriately", () => {
            // taken from https://datatracker.ietf.org/doc/html/rfc7515#section-5.1
            const expected : string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.wMe9O5ib30FnrKqxc8yHdcMCC6waAZZ7O8oP1fv8tNQ3f4iC71FWtTQ7UaK_ERrm7mmf7HYmaRsQTs-phfsy7g";
            assert.equal(output, expected)
        });
    });
});