import { SHA224, SHA256, HMAC } from "@/modules";

import { Hash } from "@/utils/types";


export const beautify = (str: string, n = 2) => {
    if (!str) return str;
    return `${str.slice(0, n)}...${str.slice(-n)}`;
};

export const createHash = (hash: Hash) => {
    switch (hash) {
        case "sha224": return new SHA224();
        case "sha256": return new SHA256();
        default: throw "Invalid argument was passed";
    };
};

export const createHmac = (hash: Hash) => {
    switch (hash) {
        case "sha224": return new HMAC(new SHA224());
        case "sha256": return new HMAC(new SHA256());
        default: throw "Invalid argument was passed";
    };
};