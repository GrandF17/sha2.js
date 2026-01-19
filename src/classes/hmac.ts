import { SHA224, SHA256 } from "@/classes";

import { HashFunc } from "@/utils/types";


export class HMAC {
    /** @abstract predefined constant inner padding - IPAD */
    readonly #IPAD = 0x36;   // 00110110

    /** @abstract predefined constant outter padding - OPAD */
    readonly #OPAD = 0x5c;   // 01011100

    /** @abstract hash function for HMAC */
    readonly #H: HashFunc;

    /** @abstract ipad XOR shared secret for HMAC */
    #ikey = new Uint8Array();

    /** @abstract opad XOR shared secret for HMAC */
    #okey = new Uint8Array();

    /** @abstract concatenated messages buffer */
    #msg = new Uint8Array();

    constructor(H: SHA224 | SHA256) {
        this.#H = H;
    };

    public init(secret: Uint8Array) {
        /** block size */
        const bs = this.#H.BSU8;
        const key = new Uint8Array(bs);

        if (secret.length > bs) {
            /** if secret size > block size */
            key.set(this.#H.update(secret).digest(), 0);
        } else {
            /** if secret size <= block size */
            key.set(secret, 0);
        };

        this.#ikey = new Uint8Array(bs);
        this.#okey = new Uint8Array(bs);

        for (let i = 0; i < bs; ++i) {
            this.#ikey[i] = this.#IPAD ^ key[i];
            this.#okey[i] = this.#OPAD ^ key[i];
        };

        /** key destruction */
        key.fill(0xde);
        key.fill(0xad);
        key.fill(0x00);

        return this;
    };

    public destroy() {
        /** opad key destruction */
        this.#ikey.fill(0xde);
        this.#ikey.fill(0xad);
        this.#ikey.fill(0x00);
        this.#ikey = new Uint8Array();

        /** ipad key destruction */
        this.#okey.fill(0xde);
        this.#okey.fill(0xad);
        this.#okey.fill(0x00);
        this.#okey = new Uint8Array();
    };

    public update(message: Uint8Array) {
        /** 
         * we assume that the data that is signed using 
         * HMAC is not secret, so it is not specifically
         * cleaning in this function
         */

        const a = new Uint8Array(this.#msg);
        const b = new Uint8Array(message);

        /** reassigning */
        this.#msg = new Uint8Array(a.length + b.length);

        /** filling with new data */
        this.#msg.set(a, 0);
        this.#msg.set(b, a.length);

        return this;
    };

    public digest() {
        /** H((IPAD XOR KEY) || MESSAGE) */
        const ipadded = this.#H
            .update(this.#ikey)
            .update(this.#msg)
            .digest();

        /** H((OPAD XOR KEY) || IPADDED) */
        const opadded = this.#H
            .update(this.#okey)
            .update(ipadded)
            .digest();

        /** msg destruction */
        this.#msg.fill(0x00);
        this.#msg = new Uint8Array();

        return opadded;
    };
};