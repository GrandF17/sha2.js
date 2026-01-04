import { expect } from "chai";

import { XChaCha20Poly1305 } from "@/classes";


describe("XChaCha20Poly1305", () => {
    /** key, nonce, aad, plaintext, ciphertext, tag */
    const tvs: [string, string, string, string, string, string][] = [
        /** special RFC tests */
        [
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "50515253c0c1c2c3c4c5c6c7",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49"
        ],
    ];

    it("encryption", () => {
        const chacha = new XChaCha20Poly1305();

        for (let i = 0; i < tvs.length; ++i) {
            const key = Buffer.from(tvs[i][0], "hex");
            const nonce = Buffer.from(tvs[i][1], "hex");
            const aad = Buffer.from(tvs[i][2], "hex");
            const plaintext = Buffer.from(tvs[i][3], "hex");
            const ciphertext = tvs[i][4];
            const tag = tvs[i][5];

            chacha.init(key, nonce);
            const result = chacha.encrypt(plaintext, aad);

            expect(Buffer.from(result).toString("hex")).to.equal(ciphertext + tag);
        };
    });

    it("decryption", () => {
        const chacha = new XChaCha20Poly1305();

        for (let i = 0; i < tvs.length; ++i) {
            const key = Buffer.from(tvs[i][0], "hex");
            const nonce = Buffer.from(tvs[i][1], "hex");
            const aad = Buffer.from(tvs[i][2], "hex");
            const plaintext = tvs[i][3];
            const ciphertext = Buffer.from(tvs[i][4], "hex");
            const tag = Buffer.from(tvs[i][5], "hex");

            chacha.init(key, nonce);
            const result = chacha.decrypt(new Uint8Array([...ciphertext, ...tag]), aad);

            expect(Buffer.from(result).toString("hex")).to.equal(plaintext);
        };
    });
});