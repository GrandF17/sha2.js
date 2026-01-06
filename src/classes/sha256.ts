import { SHA256_IV, SHA256_K } from "@/computed/constants";

export class SHA256 {
    /** 
     * block size (Uint8)
     * @default 64 bytes (512 bits)
     * @overrideable
     */
    public readonly BSU8 = 64;

    /** 
     * block size (Uint32)
     * @default 16 words
     * @overrideable
     */
    public readonly BSU32 = this.BSU8 / 4;

    /**
     * return block size (Uint8)
     * @default 32 bytes (256 bits)
     * @overrideable
     */
    public readonly RBSU8 = this.BSU8 / 2;

    /**
     * return block size (Uint32)
     * @default 8 words
     * @overrideable
     */
    public readonly RBSU32 = this.RBSU8 / 4;

    /** current state of SHA function */
    #state = new Uint32Array(SHA256_IV);

    /** reusable buffer */
    #buff = new Uint32Array(this.BSU8);

    constructor() { };

    ////////////////////////////////////////////////////////////////
    //////////////////////////// PUBLIC ///////////////////////////

    /** @overrideable */
    public update(x: Uint8Array) {
        const bitLen = x.length * 8;

        // +1 байт (0x80) +8 байт (length)
        const totalLen = x.length + 1 + 8;
        const paddedLen = Math.ceil(totalLen / 64) * 64;

        const buff = new Uint8Array(paddedLen);
        buff.set(x);
        buff[x.length] = 0x80;

        const view = new DataView(buff.buffer);
        view.setUint32(paddedLen - 4, bitLen >>> 0, false);
        view.setUint32(paddedLen - 8, Math.floor(bitLen / 2 ** 32), false);

        const end = buff.length / this.BSU8;
        for (let i = 0; i < end; ++i) {
            this.core();
        };

        return this;
    };

    /** @overrideable */
    public digest(): Uint8Array {
        const out = new Uint8Array(32);
        const view = new DataView(out.buffer);

        for (let i = 0; i < 8; ++i) {
            view.setUint32(i * 4, this.#state[i], false);
        };

        this.#state.set(SHA256_IV);
        this.#buff.fill(0);

        return out;
    };

    ////////////////////////////////////////////////////////////////
    ////////////////////////// PROTECTED //////////////////////////

    /** @overrideable */
    protected core() {
        const view = new DataView(this.#buff.buffer);

        /**
         * 1) extend the first 16 words into 
         * the remaining * 48 words w[16..63] 
         * of the message schedule array
         */
        for (let i = 0; i < 16; ++i) {
            /** get Uint32 in BE format */
            this.#buff[i] = view.getUint32(
                i * 4,
                false
            );
        };

        for (let i = 16; i < 64; ++i) {
            const s0 = this.#s0(this.#buff[i - 15]);
            const s1 = this.#s1(this.#buff[i - 2]);
            this.#buff[i] = (s1 + this.#buff[i - 7] + s0 + this.#buff[i - 16]) | 0;
        };

        /** 2) compress (64 rounds) */
        let [A, B, C, D, E, F, G, H] = this.#state;  // copy of local state

        for (let i = 0; i < 64; ++i) {
            const S1 = this.#S1(E);
            const S0 = this.#S0(A);

            const CH = this.#ch(E, F, G);
            const MAJ = this.#maj(A, B, C);

            const T1 = (H + S1 + CH + SHA256_K[i] + this.#buff[i]) | 0;
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

        /** 
         * 3) add the compressed 
         * chunk to the current hash value 
         */
        A = A + this.#state[0] | 0;
        B = B + this.#state[1] | 0;
        C = C + this.#state[2] | 0;
        D = D + this.#state[3] | 0;
        E = E + this.#state[4] | 0;
        F = F + this.#state[5] | 0;
        G = G + this.#state[6] | 0;
        H = H + this.#state[7] | 0;

        this.#state.set([A, B, C, D, E, F, G, H]);
    };

    ////////////////////////////////////////////////////////////////
    //////////////////////////// HIDDEN ///////////////////////////

    /** local hidden Sigma0 function (SHA-224/256) */
    #S0 = (x: number) => this.#rrot(x, 2) ^ this.#rrot(x, 13) ^ this.#rrot(x, 22);

    /** local hidden Sigma1 (SHA-224/256) */
    #S1 = (x: number) => this.#rrot(x, 6) ^ this.#rrot(x, 11) ^ this.#rrot(x, 25);

    /** local hidden sigma0 (SHA-224/256) */
    #s0 = (x: number) => this.#rrot(x, 7) ^ this.#rrot(x, 18) ^ this.#rsh(x, 3);

    /** local hidden sigma1 (SHA-224/256) */
    #s1 = (x: number) => this.#rrot(x, 17) ^ this.#rrot(x, 19) ^ this.#rsh(x, 10);

    /** local hidden Majority (SHA-224/256) */
    #maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z);

    /** local hidden Choose (SHA-224/256) */
    #ch = (x: number, y: number, z: number) => (x & y) ^ (~x & z);

    /** local hidden non-cyclic right shift (SHA-224/256) */
    #rsh = (x: number, n: number) => x >>> n;

    /** local hidden cyclic right shift (SHA-224/256) */
    #rrot = (x: number, n: number) => (x << (32 - n) | x >>> n);
};