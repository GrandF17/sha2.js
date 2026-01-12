import { expect } from "chai";

import { beautify, createHash } from "@/utils/helpers";


describe("sha256", () => {
    const sha = createHash("sha256");

    const vectors: [string, string][] = [
        /** test according to @noble/hashes */
        [
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ],
        [
            "c0e7bdbc5506ad43909ff6cf30a71c80df362155cb878d6d16c7f966de1a1a74",
            "a7ade084dc26e464830cbcf981e2cb1fe20e5b314038586defa0ed7ccca1ec9c",
        ],
        [
            "572fb42d601b0815425fa35443c43d27885a30e2b3b322c31acc0951",
            "33c97493eae5b6ce4ca4d12f5439b6e8d5e86771fbb019574d2d9564a6fad9fa",
        ],
        [
            "0ab6442e50529326ef67bdf41221eb01dba9fa0b931142f2330cf828b00b214d" +
            "15aa",
            "8c2cdfc7907578f701d07b3d73e6cf7b2c8118d0f2ac3bbb1669689414894002",
        ],
        [
            "3b6c607a17469cee72ee4f14278632d0ba88c94b724008802d539fbf3a70bb62" +
            "3dd4e0cef04e1d2158ef6a245d7f3fd8d70492205a223297a470e1fda21d25a2",
            "2369744e8cfceb4a4d4b3f66059cadfc07b067efa149d07fe9ae146290788ac7",
        ],
        [
            "767b57cee37e913dbf466ddaeeb7b4c4512d4a9d24323400ad14c651fcac2e62" +
            "49ffbd5080d97b9b8a1b55bde86d2370d8ced9ad5c7798",
            "3f9a17032bb76aa88f02ef9c33ba59035e140bbacf1e0440769351c8485f99bc"
        ],
        [
            "8e105068d8cecb30639456ee5e2ab8ff6d31206cdd19caf4d3f53ef42265f929" +
            "5082b9b47b37e20a528ca316d4e01d70af1b543203aa36cb4d7fbf7e29c7f8",
            "a1fc927bbeef9e03c8565149df64accc018f8db8e8dece5178a4cc146c696390",
        ],
        [
            "00a2437e203145e606d250a9ca69dc8c7578201a3c5356a0b6943a2bd3830893" +
            "bd7936dd9260b0a078f7866ad7d66888f450cdfd1fecceb392ae94cacb131517" +
            "6bbc929e6397b8a1d4efb36045913d1a52ffb1359aa7cba391a18c0347c2d452" +
            "19079dfd8468f19f3451591d4982621431a922ee11d77794a38c5e9a2bd3ca",
            "cd656545d3a2cf702d7d1d33196b3290b2e0d0bef67d3c5864a2537e4582dd60",
        ],
        [
            "14f49daf4be01742f218de0f45cf2e1e94a21bc3ba3cd9d991a05a91df5f9305" +
            "87119e51fffad924a48fcda76d9c0f715b3798e81cf1f9c64b94ec2a25756d8c" +
            "8cd4496e97608d662064b933082697a979441916cb392c1a01ba6d93da0f1c78" +
            "ac2ef4c0a8783cb2a6ad43577c0fcfef8b22fa2451ed5bc0de09ff9d722abb0f",
            "bd789a27393f371c3ba4270ce7230ff795acfcc183f042ce7b20db43c09f9cf2"
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
            "e03cb94ba085200f855ac83373b41cd0f486cf604c52cfbec30d5f947be2e06e"
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