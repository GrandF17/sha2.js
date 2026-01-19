import { expect } from "chai";

import { createHmac, beautify } from "@/utils/helpers";


/**
 * @abstract HMAC SHA224 tests according to 
 * https://datatracker.ietf.org/doc/html/rfc4231#page-4 
 */
describe("hmac-sha224", () => {
    const hmac = createHmac("sha224");

    /** [key, payload, result] */
    const vectors: [string, string, string][] = [
        [
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"
        ],
        [
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
        ],
        [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" +
            "dddddddddddddddddddddddddddddddddddd",
            "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
        ],
        [
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
        ],
        [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaa",
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a" +
            "65204b6579202d2048617368204b6579204669727374",
            "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
        ],
        [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468" +
            "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074" +
            "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565" +
            "647320746f20626520686173686564206265666f7265206265696e6720757365" +
            "642062792074686520484d414320616c676f726974686d2e",
            "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
        ],
    ];

    for (let i = 0; i < vectors.length; ++i) {
        const key = Buffer.from(vectors[i][0], "hex");
        const payload = vectors[i][1];
        const hash = vectors[i][2];

        it(
            `hmac(${beautify(payload, 8)}) = ${beautify(hash, 8)}`,
            () => {
                const result = hmac
                    .init(key)
                    .update(Buffer.from(payload, "hex"))
                    .digest();

                expect(Buffer.from(result).toString("hex")).to.equal(hash);
            }
        );
    };
});