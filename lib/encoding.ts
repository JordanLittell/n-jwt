export const base64URLEncode = (input: string) => {
    const utf8 = Buffer.from(input).toString("utf8");
    return Buffer.from(utf8).toString('base64url');
}