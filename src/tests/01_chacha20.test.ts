import { expect } from "chai";

import { ChaCha20 } from "@/classes";


describe("ChaCha20", () => {
    /** key, nonce, plaintext, ciphertext, counter */
    const tvs: [string, string, string, string, number][] = [
        /** special RFC tests */
        [
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000000000000004a00000000",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
            1
        ],
        [
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "070000004041424344454647",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
            1
        ],
    ];

    it("encryption", () => {
        const chacha = new ChaCha20();

        for (let i = 0; i < tvs.length; ++i) {
            const key = Buffer.from(tvs[i][0], "hex");
            const nonce = Buffer.from(tvs[i][1], "hex");
            const plaintext = Buffer.from(tvs[i][2], "hex");
            const ciphertext = tvs[i][3];
            const counter = tvs[i][4];

            chacha.init(key, nonce, counter);
            const result = chacha.encrypt(plaintext);

            expect(Buffer.from(result).toString("hex")).to.equal(ciphertext);
        };
    });

    it("decryption", () => {
        const chacha = new ChaCha20();

        for (let i = 0; i < tvs.length; ++i) {
            const key = Buffer.from(tvs[i][0], "hex");
            const nonce = Buffer.from(tvs[i][1], "hex");
            const plaintext = tvs[i][2];
            const ciphertext = Buffer.from(tvs[i][3], "hex");
            const counter = tvs[i][4];

            chacha.init(key, nonce, counter);
            const result = chacha.decrypt(ciphertext);

            expect(Buffer.from(result).toString("hex")).to.equal(plaintext);
        };
    });
});