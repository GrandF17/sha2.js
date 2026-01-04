import { expect } from "chai";

import { ChaCha20Poly1305 } from "@/classes";


describe("ChaCha20Poly1305", () => {
    /** key, nonce, aad, plaintext, ciphertext, tag */
    const tvs: [string, string, string, string, string, string][] = [
        /** special RFC tests */
        [
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "070000004041424344454647",
            "50515253c0c1c2c3c4c5c6c7",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691"
        ],
    ];

    it("encryption", () => {
        const chacha = new ChaCha20Poly1305();

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
        const chacha = new ChaCha20Poly1305();

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