export class SHA512 {
    /** block size (Uint8), @default 128 bytes (1024 bits) */
    public readonly BSU8 = 128;

    /** block size (Uint32), @default 32 words */
    public readonly BSU32 = this.BSU8 / 4;

    constructor() { };

    // ...
};