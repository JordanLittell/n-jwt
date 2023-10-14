import {JWKClient} from "@lib/jwk/JWKClient";
import {JWKS} from "@lib/jwk/JWKS";
import * as https from "https";
import {JWKParser} from "@lib/jwk/jwk-parser";
import {JWK} from "@lib/jwk/jwk";

export class HttpClient implements JWKClient {
    async fetch(url: URL, kid: string): Promise<JWK> {

        let output = '';
        return new Promise<JWK>((resolve, reject) => {
            https.request(url, (res) => {
                res.setEncoding('utf8');
                res.on('data', (chunk: any) => {
                    output += chunk;
                });

                res.on('end', () => {
                    let keys = JSON.parse(output)['keys'];
                    let jwkKeys = keys.map((key: any) => new JWKParser().parse(JSON.stringify(key)))
                    resolve(new JWKS(jwkKeys).find(kid));
                });

                res.on('error', (err) => {
                    reject(err)
                });
            })
        });
    }

}