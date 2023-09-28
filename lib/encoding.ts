export const base64URLEncode = (input: string) => {
    const utf8 = new Buffer(input).toString("utf8");
    return new Buffer(utf8).toString('base64url');
}