import { SHA224, SHA256 } from "@/classes";

/**
 * @abstract all types supported by createHash function
 */
export type Hash = "sha224" | "sha256";

/**
 * @abstract all types supported by createHmac function
 */
export type HashFunc = SHA224 | SHA256;