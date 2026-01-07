import { SHA224_IV } from "@/computed/constants";

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
    public override readonly RBSU8 = 28;

    /**
     * @abstract return block size (Uint32)
     * @default 7 words
     * @overrided
     */
    public override readonly RBSU32 = this.RBSU8 / this.BIW;

    /** 
     * @abstract SHA224 IV 
     * @overrided
     */
    protected override get IV() {
        return new Uint32Array(SHA224_IV);
    };

    constructor() {
        super();
    };
};