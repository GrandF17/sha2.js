import { SHA512_IV, SHA512_K } from "@/computed/constants";


/**
 * @abstract need this kind of type to make operations under 
 * 64-bit numbers, since JS supports only 55-bit integer values
 * numbers are conveniently presented in the BE format
 * 
 * so [0] - most significant 32-bits and [1] - less
 */
export type u64 = [number, number];

/**
 * @abstract NIST SHA-512 hash crypto-primitive
 * @link https://www.rfc-editor.org/rfc/rfc6234
 */
export class SHA512 {
    /**
     * @abstract bytes in word (Uint8 in Uint32)
     * @default 4 bytes
     * @overrideable
     */
    protected readonly BIW = 4;

    /** 
     * @abstract block size (Uint8)
     * @default 128 bytes (1024 bits)
     * @overrideable
     */
    protected readonly BSU8 = 128;

    /** 
     * block size (Uint32)
     * @default 32 words
     * @overrideable
     */
    protected readonly BSU32 = this.BSU8 / this.BIW;

    /**
     * @abstract return block size (Uint8)
     * @default 64 bytes (512 bits)
     * @overrideable
     */
    protected readonly RBSU8 = this.BSU8 / 2;

    /**
     * @abstract return block size (Uint32)
     * @default 16 words
     * @overrideable
     */
    protected readonly RBSU32 = this.RBSU8 / this.BIW;

    /** 
     * @abstract SHA IV 
     * @overrideable
     */
    protected readonly IV: Uint32Array;

    /** 
     * @abstract SHA512 K 
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
    constructor(iv = SHA512_IV, k = SHA512_K) {
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

        for (let i = 16; i < 80; ++i) {
            const s0 = this.#s0(buffer[i - 15]);
            const s1 = this.#s1(buffer[i - 2]);
            buffer[i] = (s1 + buffer[i - 7] + s0 + buffer[i - 16]);
        };

        /** 2) compress (80 rounds) */
        let [
            Ahi, Alo, Bhi, Blo, Chi, Clo, Dhi, Dlo,
            Ehi, Elo, Fhi, Flo, Ghi, Glo, Hhi, Hlo,
        ] = this.#state;  // copy of local state

        for (let i = 0; i < 80; ++i) {
            const S1 = this.#S1([E0, E1]);
            const S0 = this.#S0([A0, A1]);

            const CH = this.#ch([E0, E1], [F0, F1], [G0, G1]);
            const MAJ = this.#maj([A0, A1], [B0, B1], [C0, C1]);

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
            this.#state[0] + A0,
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

    /** local hidden Sigma0 hi (SHA-224/256) */
    #S0hi = (hi: number, lo: number): number => (
        ((lo << 4) | (hi >>> 28)) ^
        ((hi << 30) | (lo >>> 2)) ^
        ((hi << 25) | (lo >>> 7))
    );

    /** local hidden Sigma0 lo (SHA-224/256) */
    #S0lo = (hi: number, lo: number): number => (
        ((hi << 4) | (lo >>> 28)) ^
        ((lo << 30) | (hi >>> 2)) ^
        ((lo << 25) | (hi >>> 7))
    );

    /** local hidden Sigma1 hi (SHA-224/256) */
    #S1hi = (hi: number, lo: number): number => (
        ((lo << 18) | (hi >>> 14)) ^
        ((lo << 14) | (hi >>> 18)) ^
        ((hi << 23) | (lo >>> 9))
    );

    /** local hidden Sigma1 lo (SHA-224/256) */
    #S1lo = (hi: number, lo: number): number => (
        ((hi << 18) | (lo >>> 14)) ^
        ((hi << 14) | (lo >>> 18)) ^
        ((lo << 23) | (hi >>> 9))
    );

    /** local hidden sigma0 hi (SHA-224/256) */
    #s0hi = (hi: number, lo: number): number => (
        ((lo << 31) | (hi >>> 1)) ^
        ((lo << 24) | (hi >>> 8)) ^
        ((hi >>> 7))
    );

    /** local hidden sigma0 lo (SHA-224/256) */
    #s0lo = (hi: number, lo: number): number => (
        ((hi << 31) | (lo >>> 1)) ^
        ((hi << 24) | (lo >>> 8)) ^
        ((hi << 25) | (lo >>> 7))
    );

    /** local hidden sigma1 hi (SHA-384/512) */
    #s1hi = (hi: number, lo: number): number => (
        ((lo << 13) | (hi >>> 19)) ^
        ((hi << 3) | (lo >>> 29)) ^
        ((hi >>> 6))
    );

    /** local hidden sigma1 lo (SHA-384/512) */
    #s1lo = (hi: number, lo: number): number => (
        ((hi << 13) | (lo >>> 19)) ^
        ((lo << 3) | (hi >>> 29)) ^
        ((hi << 26) | (lo >>> 6))
    );

    /** local hidden Majority (SHA-384/512) */
    #maj = (x: u64, y: u64, z: u64): u64 => ([
        ((x[0] & y[0]) ^ (x[0] & z[0]) ^ (y[0] & z[0])),    // highest u32
        ((x[1] & y[1]) ^ (x[1] & z[1]) ^ (y[1] & z[1])),    // lowest u32
    ]);

    /** local hidden Choose (SHA-384/512) */
    #ch = (x: u64, y: u64, z: u64): u64 => ([
        ((x[0] & y[0]) ^ (~x[0] & z[0])),   // highest u32
        ((x[1] & y[1]) ^ (~x[1] & z[1])),   // lowest u32
    ]);
};