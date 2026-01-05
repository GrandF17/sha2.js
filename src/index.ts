/** 
 * ChaCha8/12/20 +
 * XChaCha20 + 
 * ChaCha20Poly1305 +
 * XChaCha20Poly1305 
 */

import { SHA256 } from "@/classes";

const arr = Uint8Array.from([0x10, 0x20, 0x30]);
const sha = new SHA256();
const a = sha.update(arr).digest();
console.log(Buffer.from(a).toString("hex"));