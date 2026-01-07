/** 
 * ChaCha8/12/20 +
 * XChaCha20 + 
 * ChaCha20Poly1305 +
 * XChaCha20Poly1305 
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { SHA256 } from "@/classes";


const b = sha256.create().update(new Uint8Array([0x10, 0x20])).update(new Uint8Array([0x30])).digest();
console.log(Buffer.from(b).toString("hex"));

const a = new SHA256().update(new Uint8Array([0x10, 0x20])).update(new Uint8Array([0x30])).digest();
console.log(Buffer.from(a).toString("hex"));
