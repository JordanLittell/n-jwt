import {test} from "node:test";
import {base64URLEncode} from "../lib/encoding";
import * as assert from "assert";

test("base64url encoding is consistent with RFC", () => {
    const payload : string = '{"iss":"joe",\r\n' +
        ' "exp":1300819380,\r\n' +
        ' "http://example.com/is_root":true}';

    const encodedPayload: string = base64URLEncode(payload);
    assert.equal(encodedPayload, "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");
});