import {describe} from "mocha";
import {JwkBuilder} from "../../lib/jwk/jwk-builder";
import {SigningAlgorithms} from "../../lib/jwa";
import * as assert from "assert";
import {JWKParser} from "../../lib/jwk/jwk-parser";

describe("building JWK objects", () => {

    it('works for octet keys', () => {
        const builder = new JwkBuilder();
        const jwk = builder
            .withKty('oct')
            .withUse('sig')
            .withKid('superkey')
            .withAlg(SigningAlgorithms.HS256)
            .withKeyOps(['encrypt'])
            .withOctetParams({k: 'bkagbkag'})
            .build();


        const parsed = new JWKParser().parse(jwk.serialize());
        assert.equal(parsed.kid, 'superkey');
    });

    it('works for RSA keys', () => {
        const builder = new JwkBuilder();
        const jwk = builder
            .withKty('RSA')
            .withUse('sig')
            .withKid('superkey')
            .withRSAPublicParams({n: 'fghjkl', e: 'lkj'})
            .build();


        new JWKParser().parse(jwk.serialize());
    });

});