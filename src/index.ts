/** 
 * SHA224/256/384/512 
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { SHA224, SHA256 } from "@/classes";
import { createHash } from '@/utils/helpers';
// import { createHash } from "crypto";


const paylaod = new Uint8Array(104_857_600);
const a = createHash("sha256").update(paylaod).digest();
console.log(Buffer.from(a).toString("hex"));

// const b = sha256.create().update(paylaod).digest();
// console.log(Buffer.from(b).toString("hex"));

// const c = new SHA224().update(paylaod).digest();
// console.log(Buffer.from(c).toString("hex"));

// const d = createHash("sha256").update(paylaod).digest("hex");
// console.log(d);