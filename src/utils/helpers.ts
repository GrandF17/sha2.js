import { SHA224, SHA256 } from "@/classes";

import { Hash } from "@/utils/types";


export const beautify = (str: string, n = 2) => {
    if (!str) return str;
    return `${str.slice(0, n)}...${str.slice(-n)}`;
};

export const createHash = (hash: Hash) => {
    switch (hash) {
        case "sha224": return new SHA224();
        case "sha256": return new SHA256();
        case "sha384": throw new Error("Not implemented yet");
        case "sha512": throw new Error("Not implemented yet");
    };
};