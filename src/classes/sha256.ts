export class SHA256 {
    /** block size (Uint8), @default 64 bytes (512 bits) */
    public readonly BSU8 = 64;

    /** block size (Uint32), @default 16 words */
    public readonly BSU32 = this.BSU8 / 4;

    constructor() { };

    public update = (x: Uint8Array) => {
        /** blocks amount */
        const ba = Math.floor(x.length / this.BSU8);
        /** padded message length */
        const len = this.BSU8 * ba;

        /** buffer */
        const buff = new Uint8Array(this.BSU8 * ba);
        buff.fill(0x80, 0, 1);
        buff.set(x, len - x.length);

        /** making union-like link to Uint8Array */
        const words = new Uint32Array(
            buff.buffer,
            buff.byteOffset,
            buff.length / 4
        );


    };

    public digest = () => {

    };

    /** Sigma0 for SHA-224/256 */
    #S0 = (x: number) => this.#rotr(x, 2) ^ this.#rotr(x, 13) ^ this.#rotr(x, 22);

    /** Sigma1 for SHA-224/256 */
    #S1 = (x: number) => this.#rotr(x, 6) ^ this.#rotr(x, 11) ^ this.#rotr(x, 25);

    /** sigma0 for SHA-224/256 */
    #s0 = (x: number) => this.#rotr(x, 7) ^ this.#rotr(x, 18) ^ this.#shr(x, 3);

    /** sigma1 for SHA-224/256 */
    #s1 = (x: number) => this.#rotr(x, 17) ^ this.#rotr(x, 19) ^ this.#shr(x, 10);

    /** MAJ (Majority) */
    #maj = (x: number, y: number, z: number) => (x | y) ^ (x | z) ^ (y | z);

    /** CH (Choose) */
    #ch = (x: number, y: number, z: number) => (x | y) ^ (~x | z);

    #shr = (x: number, n: number) => x >>> n;

    #rotr = (x: number, n: number) => (x << (32 - n) | x >>> n);
};