import { SHA224_IV, SHA256_K } from "@/computed/constants";

import { SHA256 } from "@/classes";


/**
 * @abstract NIST SHA-224 hash crypto-primitive
 * @link https://www.rfc-editor.org/rfc/rfc6234
 */
export class SHA224 extends SHA256 {
    /**
     * @abstract return block size (Uint8)
     * @default 28 bytes (224 bits)
     * @overrided
     */
    protected override readonly RBSU8 = 28;

    /**
     * @abstract return block size (Uint32)
     * @default 7 words
     * @overrided
     */
    protected override readonly RBSU32 = this.RBSU8 / this.BIW;

    /**
     * @param iv SHA224_IV
     * @param k SHA256_K
     */
    constructor(iv = SHA224_IV, k = SHA256_K) {
        super(iv, k);
    };
};