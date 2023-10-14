import {EC_KEY_TYPE, JWK, OCT_KEY_TYPE, RSA_KEY_TYPE} from "@lib/jwk/jwk";
import {ECPrivate, ECPublic, Octet, RSAPrivate} from "@lib/jwk/crypto-key-params";
import {JwkBuilder} from "@lib/jwk/jwk-builder";

/**
 * Parses JWK from a string
 */
export class JWKParser {

    public parse(payload: string) : JWK {
        const jwkJSON = JSON.parse(payload);

        const {kty, use, key_ops, alg, kid, jku, x5u, x5c, x5t, x5t_S256} = jwkJSON;

        const builder: JwkBuilder =  new JwkBuilder()
            .withKty(kty)
            .withKid(kid)
            .withUse(use)
            .withKeyOps(key_ops)
            .withAlg(alg)
            .withX5u(x5u)
            .withX5c(x5c)
            .withX5t(x5t)
            .withX5tS256(x5t_S256);



        switch(kty) {
            case EC_KEY_TYPE: {
                const {crv, x, y}: ECPrivate = jwkJSON;

                if(this.valuesPresent([crv, x, y])) {
                    builder
                        .withECPrivateParams({crv, x, y});
                }

                const {d}: ECPublic = jwkJSON;

                if(this.valuesPresent([d])) {
                    builder
                        .withECPublicParams({d});
                }
                const jwk = builder.build();

                if(jwk.d || jwk.crv) return jwk;

                throw new TypeError(`Missing encryption key parameters for JWK of type ${kty}`);
            }

            case RSA_KEY_TYPE: {

                const {d, n, e, p, q, dp, dq, qi, oth}: RSAPrivate = jwkJSON;
                if(this.valuesPresent([d])) {
                    return builder
                        .withRSAPrivateParams({n, e, d, p, q, dp, dq, qi, oth})
                        .build();
                }

                if(this.valuesPresent([n, e])) {
                    return builder
                        .withRSAPublicParams({n, e})
                        .build();
                }

                throw new TypeError(`Missing encryption key parameters for JWK of type ${kty}`);

            }
            case OCT_KEY_TYPE: {
                const {k}: Octet = jwkJSON;

                if (this.valuesPresent([k])) {
                    return builder
                        .withOctetParams({k})
                        .build();
                }

                throw new TypeError(`Missing encryption key parameters for JWK of type ${kty}`);
            }

            default:
                throw new TypeError("Unsupported Key type: " + kty);
        }
    }


    // eslint-disable  @typescript-eslint/no-explicit-any
    private valuesPresent(values: string[]) : boolean {
        return values.reduce((prev, curr) => (prev && !!curr), true);
    }
}