/** SHA224/256 + HMAC */

import { createHash } from "@/utils/helpers";

export { createHash, createHmac } from "@/utils/helpers";

const sha = createHash("sha256");

const paylaod = new Uint8Array(104_857_600);

/** creating hash from payload */
const result = sha.update(paylaod).digest();

/** logging the result of hash-function */
console.log("sha256():", Buffer.from(result).toString("hex"));