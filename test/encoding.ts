import {base64URLDecode, base64URLEncode} from "@lib/encoding";
import * as assert from "assert";

it("base64url encoding is consistent with RFC", () => {
    const payload : string = '{"iss":"joe",\r\n' +
        ' "exp":1300819380,\r\n' +
        ' "http://example.com/is_root":true}';

    const encodedPayload: string = base64URLEncode(payload);

    assert.equal(encodedPayload, "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");
});

it("encoding and decoding are inverse", () => {
    const payload : string = '{"iss":"joe",\r\n' +
        ' "exp":1300819380,\r\n' +
        ' "http://example.com/is_root":true}';

    assert.equal(payload, base64URLDecode(base64URLEncode(payload)));
});