import {JWK} from "@lib/jwk/jwk";

export class JWKS {

    readonly jwks : JWK[];
    constructor(jwks: JWK[]) {
        this.jwks = jwks;
    }

    /**
     * Returns
     * @param kid
     */
    public find(kid: string): JWK {
        const result = this.jwks.find((jwk: JWK) => jwk.kid === kid);
        if(!result) throw new Error(`Could not find key ${kid} in JWKS`);

        return result;
    }
}