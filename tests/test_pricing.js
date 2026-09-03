// Does the page charge what the seller demands?
//
// Run by check.sh. The gatekeeper is the authority: it is the thing that
// actually refuses an underpayment, so its answer is the expected value and
// the page's is what gets compared against it.
import { priceOf } from "../ui/pricing.js";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const config = JSON.parse(readFileSync(new URL("../site/config.json", import.meta.url)));
const skus = ["all", "t0", "t3", "t8", "m01", "m036", "m012345678", "m330", "m3"];

const expected = JSON.parse(execFileSync("python3", ["-c", `
import sys, json
sys.path.insert(0, "gatekeeper")
import gatekeeper as G
print(json.dumps({s: G.price_of(s) for s in ${JSON.stringify(skus)}}))
`], { cwd: new URL("..", import.meta.url).pathname, encoding: "utf8" }));

let failed = 0;
for (const sku of skus) {
  const mine = priceOf(sku, config);
  const theirs = expected[sku];
  const ok = mine === theirs;
  if (!ok) failed++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${sku.padEnd(12)} page ${String(mine).padStart(9)}  seller ${String(theirs).padStart(9)}`);
}
console.log(`\n${skus.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
