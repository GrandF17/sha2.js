import { SHA256_IV, SHA256_K } from "@/constants/constants";


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
    public readonly BSU8 = 64;

    /** 
     * block size (Uint32)
     * @default 16 words
     * @overrideable
     */
    public readonly BSU32 = this.BSU8 / this.BIW;

    /**
     * @abstract return block size (Uint8)
     * @default 32 bytes (256 bits)
     * @overrideable
     */
    public readonly RBSU8 = this.BSU8 / 2;

    /**
     * @abstract return block size (Uint32)
     * @default 8 words
     * @overrideable
     */
    public readonly RBSU32 = this.RBSU8 / this.BIW;

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

    /** @abstract view of reusable buffer */
    #buffView: DataView;

    /** @abstract reusable core-buffer for extention */
    #buffCore: Uint32Array;

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
        this.#buffView = new DataView(this.#buff.buffer);

        this.#buffCore = new Uint32Array(this.BSU8);

        this.#p = 0;
        this.#t = 0;
    };

    ////////////////////////////////////////////////////////////////
    //////////////////////////// PUBLIC ///////////////////////////

    /** @overrideable */
    public update(x: Uint8Array) {
        for (let offset = 0; offset < x.length; /** */) {
            offset = this.x2buff(x, offset);

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
        this.#buffView.setBigUint64(
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
        /** local links to variables */
        const buffCore = this.#buffCore;
        const buffView = this.#buffView;
        const state = this.#state;
        const K = this.K;

        /** local links to functions */
        const s0 = this.#s0;
        const s1 = this.#s1;
        const S0 = this.#S0;
        const S1 = this.#S1;
        const ch = this.#ch;
        const maj = this.#maj;

        /**
         * 1) extend the first 16 words into 
         * the remaining * 48 words w[16..63] 
         * of the message schedule array
         */
        for (let i = 0; i < this.BSU32; ++i) {
            /** get Uint32 in BE format */
            buffCore[i] = buffView.getUint32(
                i * 4,
                false
            );
        };

        for (let i = 16; i < 64; ++i) {
            buffCore[i] = (
                s1(buffCore[i - 2]) +
                s0(buffCore[i - 15]) +
                buffCore[i - 7] +
                buffCore[i - 16]
            );
        };

        /** 2) compress (64 rounds) */
        let A = state[0], B = state[1], C = state[2], D = state[3];
        let E = state[4], F = state[5], G = state[6], H = state[7];

        for (let i = 0; i < 64; ++i) {
            const T1 = (H + S1(E) + ch(E, F, G) + K[i] + buffCore[i]);
            const T2 = (S0(A) + maj(A, B, C));

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
        state[0] += A; state[1] += B; state[2] += C; state[3] += D;
        state[4] += E; state[5] += F; state[6] += G; state[7] += H;
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

    /** @abstract local Sigma0 (SHA-224/256) */
    #S0 = (x: number) => (
        (x << 30 | x >>> 2) ^   // right rotate (2)
        (x << 19 | x >>> 13) ^  // right rotate (13)
        (x << 10 | x >>> 22)    // right rotate (22)
    );

    /** @abstract local Sigma1 (SHA-224/256) */
    #S1 = (x: number) => (
        (x << 26 | x >>> 6) ^   // right rotate (6)
        (x << 21 | x >>> 11) ^  // right rotate (11)
        (x << 7 | x >>> 25)     // right rotate (25)
    );

    /** @abstract local sigma0 (SHA-224/256) */
    #s0 = (x: number) => (
        (x << 25 | x >>> 7) ^   // right rotate (7)
        (x << 14 | x >>> 18) ^  // right rotate (18)
        (x >>> 3)               // right shift (3)
    );

    /** @abstract local sigma1 (SHA-224/256) */
    #s1 = (x: number) => (
        (x << 15 | x >>> 17) ^  // right rotate (17)
        (x << 13 | x >>> 19) ^  // right rotate (19)
        (x >>> 10)              // right shift (10)
    );

    /** 
     * @abstract local Majority (SHA-224/256) 
     * @canonical (x & y) ^ (x & z) ^ (y & z)
    */
    #maj = (x: number, y: number, z: number) => (x & y) | (z & (x | y));

    /** @abstract local Choose (SHA-224/256) */
    #ch = (x: number, y: number, z: number) => (x & y) ^ (~x & z);
};