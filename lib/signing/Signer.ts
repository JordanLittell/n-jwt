export default interface Signer {
    sign (message: string) : string;
    digest (message: string) : string;
}