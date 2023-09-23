import {Header} from "../jose";
import {Algorithm} from "../jwa";
import * as crypto from "crypto";

/**
 * Signing algorithm is derived from JOSE headers
 * Any keys that fall in Headers is fair game for this object type
 */
export type SignerParams = Record<Header, string>;

// export default class SignerFactory {
//     static getInstance(signingParams: SignerParams)  {
//         switch (signingParams.alg) {
//             case(Algorithm.HS512.valueOf()):
//                 const hmac = crypto.createHmac('sha512', )
//         }
//     }
// }