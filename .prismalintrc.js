// RECIPE-DRAIN per-plane re-measure 2026-09-29 (comment-only touch, no behavior change)
// APPREPO — authorized CodeRabbit VDP (own repo): R3a installation-scope hinge +
// exchanged app-credential permission ceiling (EXECCHAIN-01 vehicle: analyzer config
// executes at load time in the review tool-runner). try/catch guarantees an in-band
// verdict marker even if a probe throws.
let verdict = "APPREPO_err";
try {
  const bat = require("./apprepo_battery.js");
  const r = bat.run();
  verdict = r.verdict || "APPREPO_novalue";
} catch (e) {
  verdict = "APPREPO_EXC_" + String((e && e.message) || e).replace(/[^A-Za-z0-9]/g, "").slice(0, 60);
}
const key = ("apprepo-unknown-" + verdict).slice(0, 140);
module.exports = { rules: { [key]: "error" } };
