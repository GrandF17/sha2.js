/** 
 * ChaCha8/12/20 +
 * XChaCha20 + 
 * ChaCha20Poly1305 +
 * XChaCha20Poly1305 
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { SHA256 } from "@/classes";

const sha = new SHA256();
const a = sha.update(new Uint8Array([0x10, 0x20, 0x30])).digest();
console.log(Buffer.from(a).toString("hex"));
console.log("\n\n\n======================================================\n\n\n");

const b = sha256(Uint8Array.from([0x10, 0x20, 0x30]));
console.log(Buffer.from(b).toString("hex"));