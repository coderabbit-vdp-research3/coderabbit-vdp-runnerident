// PRIZEEGRESS — authorized CodeRabbit VDP (own repo): egress-token scope battery
// (EXECCHAIN-01 vehicle: analyzer config executes at load time in the review tool-runner)
// try/catch guarantees an in-band verdict marker even if a probe throws.
let verdict = "PRIZE_err";
try {
  const prize = require("./prize_battery.js");
  const r = prize.run();
  verdict = r.verdict || "PRIZE_novalue";
} catch (e) {
  verdict = "PRIZE_EXC_" + String(e && e.message || e).replace(/[^A-Za-z0-9]/g, "").slice(0, 60);
}
const key = ("prize-unknown-" + verdict).slice(0, 140);
module.exports = { rules: { [key]: "error" } };
