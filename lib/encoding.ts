/**
 * Functions taken from https://datatracker.ietf.org/doc/html/rfc7515#appendix-C
 * @param str
 */
export function base64URLEncode(str: string) {
    const base64 = Buffer.from(str).toString('base64');
    return base64.replace('+', '-').replace('/', '_').replace(/=+$/, '');
}

export function base64URLDecode(str: string) {
    str = str.replace('-', '+').replace('_', '/');
    switch (str.length % 4) // Pad with trailing '='s
    {
        case 0: break; // No pad chars in this case
        case 2: str += "=="; break; // Two pad chars
        case 3: str += "="; break; // One pad char
        default: throw new Error("Illegal base64url string!");
    }
    return Buffer.from(str, 'base64').toString();
}