/** SHA224/256 */

import { createHmac } from "@/utils/helpers";
import { SHA256 } from "./classes";
import { HMAC } from "./classes/hmac";

export { createHash } from "@/utils/helpers";

const key = Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex");
const data = Buffer.from("4869205468657265", "hex");

const hmac = createHmac("sha256").init(key);

console.log(Buffer.from(hmac.update(data).digest()).toString("hex"))