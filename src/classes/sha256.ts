import { SHA256_IV, SHA256_K } from "@/computed/constants";

export class SHA256 {
    /** block size (Uint8), @default 64 bytes (512 bits) */
    public readonly BSU8 = 64;

    /** block size (Uint32), @default 16 words */
    public readonly BSU32 = this.BSU8 / 4;

    /** current state of SHA function */
    protected state = new Uint32Array(SHA256_IV);

    /** reusable buffer */
    protected buff = new Uint32Array(this.BSU8);

    constructor() { };

    public update(x: Uint8Array) {
        const ba = Math.ceil(x.length / this.BSU8);     // blocks amount
        const len = this.BSU8 * ba;                     // padded message length

        const buff = new Uint8Array(this.BSU8 * ba);    // buffer
        buff.fill(0x80, 0, 1);
        buff.set(x, len - x.length);

        /** simple DataView to easily get operate bytes */
        const view = new DataView(
            buff.buffer,
            buff.byteOffset,
            buff.byteLength,
        );

        for (let offset = 0; offset < buff.length;) {
            /**
             * 1) extend the first 16 words into the remaining 
             * 48 words w[16..63] of the message schedule array
             */
            for (let i = 0; i < 16; ++i, offset += 4) {
                /** get Uint32 in BE format */
                this.buff[i] = view.getUint32(offset);
            };

            for (let i = 16; i < 64; ++i) {
                const s0 = this.#s0(this.buff[i - 15]);
                const s1 = this.#s1(this.buff[i - 2]);
                this.buff[i] = (s1 + this.buff[i - 7] + s0 + this.buff[i - 16]);
            };

            /** 2) compress (64 rounds) */
            let [A, B, C, D, E, F, G, H] = this.state;  // copy of local state
            for (let i = 0; i < 64; ++i) {
                const S1 = this.#S1(E);
                const S0 = this.#S0(A);
                const T1 = (H + S1 + this.#ch(E, F, G) + SHA256_K[i] + this.buff[i]) | 0;
                const T2 = (S0 + this.#maj(A, B, C)) | 0;
                H = G;
                G = F;
                F = E;
                E = (D + T1) | 0;
                D = C;
                C = B;
                B = A;
                A = (T1 + T2) | 0;
            };

            /** 3) add the compressed chunk to the current hash value */
            A = A + this.state[0];
            B = B + this.state[1];
            C = C + this.state[2];
            D = D + this.state[3];
            E = E + this.state[4];
            F = F + this.state[5];
            G = G + this.state[6];
            H = H + this.state[7];

            this.state.set([A, B, C, D, E, F, G, H]);
        };

        return this;
    };

    public digest() {
        const result = new Uint32Array(this.state);
        console.log(Buffer.from(result.buffer).toString("hex"));

        this.state.set(SHA256_IV);
        this.buff.fill(0x00);

        return new Uint8Array(
            result.buffer,
            result.byteOffset,
            result.length * 4
        );
        // bb1d087da9cbec26091ab1369fba0519bed5bf050e0143e539da09e859ea01ec
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