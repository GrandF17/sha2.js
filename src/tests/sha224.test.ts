import { expect } from "chai";

import { SHA224 } from "@/classes";
import { beautify } from "@/utils/helpers";


describe("Sha224", () => {
    const sha = new SHA224();

    const vectors: [string, string][] = [
        /** test according to @noble/hashes */
        [
            "",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        ],
        [
            "c0e7bdbc5506ad43909ff6cf30a71c80df362155cb878d6d16c7f966de1a1a74",
            "be253be33c0bc4dae9d74f821c681eece8d1733dafb26e6a98e7679b",
        ],
        [
            "572fb42d601b0815425fa35443c43d27885a30e2b3b322c31acc0951",
            "0b28bbe7055fceb6ff17e049fffb2ccb77fff28091c8787dd7c9605c",
        ],
        [
            "0ab6442e50529326ef67bdf41221eb01dba9fa0b931142f2330cf828b00b214d" +
            "15aa",
            "3f352da63a0650e7147afdb9a81b4f609064241338a65ca12e64a12d",
        ],
        [
            "3b6c607a17469cee72ee4f14278632d0ba88c94b724008802d539fbf3a70bb62" +
            "3dd4e0cef04e1d2158ef6a245d7f3fd8d70492205a223297a470e1fda21d25a2",
            "a495e8085682f7d3be1742a1f64363af557b13e6f275802ad79535b9",
        ],
        [
            "767b57cee37e913dbf466ddaeeb7b4c4512d4a9d24323400ad14c651fcac2e62" +
            "49ffbd5080d97b9b8a1b55bde86d2370d8ced9ad5c7798",
            "c8c1a87ede066466f420b5ebe475f4caedea1cd2bd7fa4c58fd0d00f"
        ],
        [
            "8e105068d8cecb30639456ee5e2ab8ff6d31206cdd19caf4d3f53ef42265f929" +
            "5082b9b47b37e20a528ca316d4e01d70af1b543203aa36cb4d7fbf7e29c7f8",
            "cd998a6e6ccc71afc00b2849349c9e58cd9a13c8fe693a876b476038",
        ],
        [
            "00a2437e203145e606d250a9ca69dc8c7578201a3c5356a0b6943a2bd3830893" +
            "bd7936dd9260b0a078f7866ad7d66888f450cdfd1fecceb392ae94cacb131517" +
            "6bbc929e6397b8a1d4efb36045913d1a52ffb1359aa7cba391a18c0347c2d452" +
            "19079dfd8468f19f3451591d4982621431a922ee11d77794a38c5e9a2bd3ca",
            "d1962e7d906f93c18e2f11164c6103e71b85ad905275955dda0b498d",
        ],
        [
            "14f49daf4be01742f218de0f45cf2e1e94a21bc3ba3cd9d991a05a91df5f9305" +
            "87119e51fffad924a48fcda76d9c0f715b3798e81cf1f9c64b94ec2a25756d8c" +
            "8cd4496e97608d662064b933082697a979441916cb392c1a01ba6d93da0f1c78" +
            "ac2ef4c0a8783cb2a6ad43577c0fcfef8b22fa2451ed5bc0de09ff9d722abb0f",
            "d09bfdf719ac3ea6e50ffe3cffa9f32ac49224aba99dd93b1c70c1a6"
        ],
        [
            "769ab959c7b85c5e270253f61ba816bef6e67651250f4057ef79e683539cb3e7" +
            "4970664cccf52050dcd224ad4edac844e288b633dda1f5db89f01d2b16ba41e2" +
            "5fa233ebb365a8e4a9b1bf5c4ca1d39d862d1dc9cfccdff6fd00986b658fb743" +
            "447377e7ab1e987ac2e93ee2c7d89598b586669046d02f29213f73249ad529b1" +
            "9fb69063ac2f9ed516622aff7134e5cdabc4c3f06f77777c6ecb72354ed94a4a" +
            "10ef3a0024d5ea7b5d6e1d4655f7bc198397260de8340e5b881bdf136a805ad1" +
            "d3f8a9d984fa35a805d7b92bbea47cf337c78fb6735411c3590255d6403060f8" +
            "fb6ab4398b3270922e04f5f55f24eac4c14af01e12401e08eb4d9dc0ff91f2f2",
            "b34c80d636f07383ea1c9bf32a3a70fbf6bdde47c40295ade4d00b93"
        ]
    ];

    for (let i = 0; i < vectors.length; ++i) {
        const plaintext = vectors[i][0];
        const hash = vectors[i][1];

        it(
            `hash(${beautify(plaintext, 8)}) = ${beautify(hash, 8)}`,
            () => {
                const result = sha.update(Buffer.from(plaintext, "hex")).digest();
                expect(Buffer.from(result).toString("hex")).to.equal(hash);
            }
        );
    };
});