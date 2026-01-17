/** SHA224/256 */

export { createHash } from "@/utils/helpers";

import { createHash } from '@/utils/helpers';

const paylaod = new Uint8Array(104_857_600);
const a = createHash("sha256").update(paylaod).digest();
console.log(Buffer.from(a).toString("hex"));