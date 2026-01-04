/** @abstract Uint8Array[] => Uint8Array */
export const concatU8Arr = (arrays: Uint8Array[]): Uint8Array => {
    const len = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const res = new Uint8Array(len);

    let offset = 0;
    for (let i = 0; i < arrays.length; ++i) {
        res.set(arrays[i], offset);
        offset += arrays[i].length;
    };

    return res;
};

/** @abstract Uint32Array[] => Uint32Array */
export const concatU32Arr = (arrays: Uint32Array[]): Uint32Array => {
    const len = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const res = new Uint32Array(len);

    let offset = 0;
    for (let i = 0; i < arrays.length; ++i) {
        res.set(arrays[i], offset);
        offset += arrays[i].length;
    };

    return res;
};