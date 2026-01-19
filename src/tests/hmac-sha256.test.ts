import { expect } from "chai";

import { createHmac, beautify } from "@/utils/helpers";


/**
 * @abstract HMAC SHA224 tests according to 
 * https://datatracker.ietf.org/doc/html/rfc4231#page-4 
 */
describe("hmac-sha256", () => {
    const hmac = createHmac("sha256");

    /** [key, payload, result] */
    const vectors: [string, string, string][] = [
        [
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        ],
        [
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ],
        [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" +
            "dddddddddddddddddddddddddddddddddddd",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ],
        [
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ],
        [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaa",
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a" +
            "65204b6579202d2048617368204b6579204669727374",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
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
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
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