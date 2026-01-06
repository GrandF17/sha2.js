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
        const buff = new Uint8Array(this.BSU8 * ba);    // buffer
        buff.set(x, 0);
        buff[x.length] = 0x80;
        buff[buff.length - 1] = 0x18;

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
                const CH = this.#ch(E, F, G);
                const MAJ = this.#maj(A, B, C);
                const T1 = (H + S1 + CH + SHA256_K[i] + this.buff[i]) | 0;
                const T2 = (S0 + MAJ) | 0;
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
            A = A + this.state[0] | 0;
            B = B + this.state[1] | 0;
            C = C + this.state[2] | 0;
            D = D + this.state[3] | 0;
            E = E + this.state[4] | 0;
            F = F + this.state[5] | 0;
            G = G + this.state[6] | 0;
            H = H + this.state[7] | 0;
            console.log([A, B, C, D, E, F, G, H].toString());

            this.state.set([A, B, C, D, E, F, G, H]);
        };

        return this;
    };

    public digest() {
        const result = new Uint32Array(this.state);

        this.state.set(SHA256_IV);
        this.buff.fill(0x00);

        return new Uint8Array(
            result.buffer,
            result.byteOffset,
            result.length * 4
        );
    };

    /** Sigma0 for SHA-224/256 */
    #S0 = (x: number) => this.#rrot(x, 2) ^ this.#rrot(x, 13) ^ this.#rrot(x, 22);

    /** Sigma1 for SHA-224/256 */
    #S1 = (x: number) => this.#rrot(x, 6) ^ this.#rrot(x, 11) ^ this.#rrot(x, 25);

    /** sigma0 for SHA-224/256 */
    #s0 = (x: number) => this.#rrot(x, 7) ^ this.#rrot(x, 18) ^ this.#rsh(x, 3);

    /** sigma1 for SHA-224/256 */
    #s1 = (x: number) => this.#rrot(x, 17) ^ this.#rrot(x, 19) ^ this.#rsh(x, 10);

    /** MAJ (Majority) */
    #maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z);

    /** CH (Choose) */
    #ch = (x: number, y: number, z: number) => (x & y) ^ (~x & z);

    /** right shift (non-cyclic) */
    #rsh = (x: number, n: number) => x >>> n;

    /** right rotate (cyclic right shift) */
    #rrot = (x: number, n: number) => (x << (32 - n) | x >>> n);
};