import { SHA256_IV, SHA256_K } from "@/computed/constants";


/**
 * @abstract NIST SHA-256 hash crypto-primitive
 * @link https://www.rfc-editor.org/rfc/rfc6234
 */
export class SHA256 {
    /**
     * @abstract bytes in word (Uint8 in Uint32)
     * @default 4 bytes
     * @overrideable
     */
    protected readonly BIW = 4;

    /** 
     * @abstract block size (Uint8)
     * @default 64 bytes (512 bits)
     * @overrideable
     */
    protected readonly BSU8 = 64;

    /** 
     * block size (Uint32)
     * @default 16 words
     * @overrideable
     */
    protected readonly BSU32 = this.BSU8 / this.BIW;

    /**
     * @abstract return block size (Uint8)
     * @default 32 bytes (256 bits)
     * @overrideable
     */
    protected readonly RBSU8 = this.BSU8 / 2;

    /**
     * @abstract return block size (Uint32)
     * @default 8 words
     * @overrideable
     */
    protected readonly RBSU32 = this.RBSU8 / this.BIW;

    /** 
     * @abstract SHA IV 
     * @overrideable
     */
    protected readonly IV: Uint32Array;

    /** 
     * @abstract SHA256 K 
     * @overrideable
     */
    protected readonly K: Uint32Array;

    /** @abstract current state of SHA function */
    #state: Uint32Array;

    /** @abstract reusable buffer */
    #buff: Uint8Array;

    /** @abstract buffer pointer */
    #p: number;

    /** @abstract total bytes hashed */
    #t: number;

    /**
     * @param iv SHA256_IV
     * @param k SHA256_K
     */
    constructor(iv = SHA256_IV, k = SHA256_K) {
        this.IV = new Uint32Array(iv);
        this.K = new Uint32Array(k);

        this.#state = new Uint32Array(iv);
        this.#buff = new Uint8Array(this.BSU8);
        this.#p = 0;
        this.#t = 0;
    };

    ////////////////////////////////////////////////////////////////
    //////////////////////////// PUBLIC ///////////////////////////

    /** @overrideable */
    public update(x: Uint8Array) {
        let i = 0;
        while (i < x.length) {
            i = this.x2buff(x, i);

            if (this.#p === this.BSU8) {
                this.core();
                this.cleanBuff();
            };
        };

        this.#t += x.length;
        return this;
    };

    /** @overrideable */
    public digest() {
        /** 
         * start of the padding 
         * bit sequence: 10000000... 
         */
        this.#buff[this.#p++] = 0x80;

        /** 
         * if there is not enough place for total hased data length =>
         * run core function and fill buffer one more time 
         */
        if (this.#p > (this.BSU8 - 8)) {
            this.core();
            this.cleanBuff();
        };

        /** setting length to the end of buffer and run core function */
        new DataView(this.#buff.buffer).setBigUint64(
            this.BSU8 - 8,
            BigInt(this.#t) * 8n,
            false
        );
        this.core();

        const out = new Uint8Array(this.RBSU8);
        const view = new DataView(out.buffer);

        for (let i = 0; i < this.RBSU32; ++i) {
            view.setUint32(
                i * this.BIW,
                this.#state[i],
                false
            );
        };

        /** cleaning */
        this.cleanState();
        this.cleanBuff();

        return out;
    };

    ////////////////////////////////////////////////////////////////
    ////////////////////////// PROTECTED //////////////////////////

    /** @overrideable */
    protected core() {
        const view = new DataView(this.#buff.buffer);
        const buffer = new Uint32Array(this.BSU8);

        /**
         * 1) extend the first 16 words into 
         * the remaining * 48 words w[16..63] 
         * of the message schedule array
         */
        for (let i = 0; i < this.BSU32; ++i) {
            /** get Uint32 in BE format */
            buffer[i] = view.getUint32(
                i * 4,
                false
            );
        };

        for (let i = 16; i < 64; ++i) {
            const s0 = this.#s0(buffer[i - 15]);
            const s1 = this.#s1(buffer[i - 2]);
            buffer[i] = (
                s1 +
                s0 +
                buffer[i - 7] +
                buffer[i - 16]
            );
        };

        /** 2) compress (64 rounds) */
        let [A, B, C, D, E, F, G, H] = this.#state;  // copy of local state

        for (let i = 0; i < 64; ++i) {
            const S1 = this.#S1(E);
            const S0 = this.#S0(A);

            const CH = this.#ch(E, F, G);
            const MAJ = this.#maj(A, B, C);

            const T1 = (H + S1 + CH + this.K[i] + buffer[i]);
            const T2 = (S0 + MAJ);

            H = G;
            G = F;
            F = E;
            E = D + T1;
            D = C;
            C = B;
            B = A;
            A = T1 + T2;
        };

        /** 
         * 3) add the compressed chunk
         * to the current hash value 
         */
        this.#state.set([
            this.#state[0] + A,
            this.#state[1] + B,
            this.#state[2] + C,
            this.#state[3] + D,
            this.#state[4] + E,
            this.#state[5] + F,
            this.#state[6] + G,
            this.#state[7] + H,
        ]);
    };

    /** @overrideable */
    protected x2buff(x: Uint8Array, offset: number): number {
        while (this.#p < this.#buff.length && offset < x.length) {
            this.#buff[this.#p++] = x[offset++];
        };

        return offset;
    };

    /** @overrideable */
    protected cleanBuff() {
        this.#buff.fill(0x00);
        this.#p = 0;
    };

    /** @overrideable */
    protected cleanState() {
        this.#state.set(this.IV);
        this.#t = 0;
    };

    ////////////////////////////////////////////////////////////////
    //////////////////////////// HIDDEN ///////////////////////////

    /** local Sigma0 (SHA-224/256) */
    #S0 = (x: number) => (
        (x << 30 | x >>> 2) ^   // right rotate (2)
        (x << 19 | x >>> 13) ^  // right rotate (13)
        (x << 10 | x >>> 22)    // right rotate (22)
    );

    /** local Sigma1 (SHA-224/256) */
    #S1 = (x: number) => (
        (x << 26 | x >>> 6) ^   // right rotate (6)
        (x << 21 | x >>> 11) ^  // right rotate (11)
        (x << 7 | x >>> 25)     // right rotate (25)
    );

    /** local sigma0 (SHA-224/256) */
    #s0 = (x: number) => (
        (x << 25 | x >>> 7) ^   // right rotate (7)
        (x << 14 | x >>> 18) ^  // right rotate (18)
        (x >>> 3)               // right shift (3)
    );

    /** local sigma1 (SHA-224/256) */
    #s1 = (x: number) => (
        (x << 15 | x >>> 17) ^  // right rotate (17)
        (x << 13 | x >>> 19) ^  // right rotate (19)
        (x >>> 10)              // right shift (10)
    );

    /** local Majority (SHA-224/256) */
    #maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z);

    /** local Choose (SHA-224/256) */
    #ch = (x: number, y: number, z: number) => (x & y) ^ (~x & z);
};