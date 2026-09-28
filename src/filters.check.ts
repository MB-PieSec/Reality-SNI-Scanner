// Run: node src/filters.check.ts
import assert from "node:assert/strict";
import { isAcceptableDomain as ok } from "./filters.ts";

for (const d of ["netflix.com", "dropbox.com", "alphabet.com", "fedex.com", "www.betterhelp.com"]) assert(ok(d), d);
for (const d of ["x.com", "www.youtube.com", "bet365.com", "www.1xbet.com", "a.xxx.com", "m.facebook.com"]) assert(!ok(d), d);
console.log("filters ok");
