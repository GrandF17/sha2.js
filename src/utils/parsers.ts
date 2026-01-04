export const bigIntToU8LE = (n: bigint, s = 8) => {
    const out = new Uint8Array(s);

    for (let i = 0; i < s; ++i) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
    };

    return out;
};