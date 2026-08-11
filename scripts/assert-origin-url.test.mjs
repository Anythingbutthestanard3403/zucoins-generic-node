import assert from "node:assert/strict";
import test from "node:test";

import {
  assertOriginUrl,
  CANONICAL_ORIGIN_URL,
  CANONICAL_OWNER_REPO,
  checkOriginRemote,
  classifyOriginUrl,
  formatFailureMessage,
  REPAIR_COMMAND,
} from "./assert-origin-url.mjs";

// --- the four required url-shape cases ------------------------------------

test("GitHub https url → pass", () => {
  const url = "https://github.com/Anythingbutthestanard3403/zucoins-generic-node.git";
  const classified = classifyOriginUrl(url);
  assert.deepEqual(classified, { ok: true, form: "https" });
  assert.equal(assertOriginUrl(url).status, "ok");
});

test("git@github.com: ssh form → pass", () => {
  const url = "git@github.com:Anythingbutthestanard3403/zucoins-generic-node.git";
  const classified = classifyOriginUrl(url);
  assert.deepEqual(classified, { ok: true, form: "ssh" });
  assert.equal(assertOriginUrl(url).status, "ok");
});

test("local absolute path → fail with repair command", () => {
  const url = "/Volumes/Ai Building/Zucoins Merchant Wallets";
  const classified = classifyOriginUrl(url);
  assert.equal(classified.ok, false);
  assert.equal(classified.reason, "ORIGIN_IS_LOCAL_PATH");

  const result = assertOriginUrl(url);
  assert.equal(result.status, "invalid");
  assert.equal(result.reason, "ORIGIN_IS_LOCAL_PATH");
  assert.equal(result.repair, REPAIR_COMMAND);
  assert.match(formatFailureMessage(result), /git remote set-url origin/);
  assert.match(formatFailureMessage(result), /Anythingbutthestanard3403\/zucoins-generic-node/);
});

test("different GitHub repo → fail", () => {
  const url = "https://github.com/other-org/other-repo.git";
  const classified = classifyOriginUrl(url);
  assert.equal(classified.ok, false);
  assert.equal(classified.reason, "ORIGIN_WRONG_GITHUB_REPO");
  assert.equal(assertOriginUrl(url).status, "invalid");
});

// --- adjacent forms the check must also accept / reject -------------------

test("https without .git suffix still passes", () => {
  const url = "https://github.com/Anythingbutthestanard3403/zucoins-generic-node";
  assert.equal(assertOriginUrl(url).status, "ok");
});

test("ssh://git@github.com/ form passes", () => {
  const url = "ssh://git@github.com/Anythingbutthestanard3403/zucoins-generic-node.git";
  assert.deepEqual(classifyOriginUrl(url), { ok: true, form: "ssh-url" });
});

test("file:// local path fails", () => {
  assert.equal(
    classifyOriginUrl("file:///Volumes/Ai Building/Zucoins Merchant Wallets").reason,
    "ORIGIN_IS_LOCAL_PATH",
  );
});

test("relative local path fails", () => {
  assert.equal(classifyOriginUrl("../some-other-clone").reason, "ORIGIN_IS_LOCAL_PATH");
});

test("empty / non-string fails", () => {
  assert.equal(classifyOriginUrl("").reason, "ORIGIN_URL_EMPTY");
  assert.equal(classifyOriginUrl(undefined).reason, "ORIGIN_URL_EMPTY");
  assert.equal(classifyOriginUrl(null).reason, "ORIGIN_URL_EMPTY");
});

test("checkOriginRemote uses injectable getUrl (no git required)", () => {
  const ok = checkOriginRemote({
    getUrl: () => CANONICAL_ORIGIN_URL,
  });
  assert.equal(ok.status, "ok");

  const bad = checkOriginRemote({
    getUrl: () => "/tmp/poisoned-clone",
  });
  assert.equal(bad.status, "invalid");
  assert.equal(bad.reason, "ORIGIN_IS_LOCAL_PATH");
});

test("REPAIR_COMMAND and CANONICAL_* are stable for docs/scripts to cite", () => {
  assert.equal(
    CANONICAL_ORIGIN_URL,
    "https://github.com/Anythingbutthestanard3403/zucoins-generic-node.git",
  );
  assert.equal(CANONICAL_OWNER_REPO, "Anythingbutthestanard3403/zucoins-generic-node");
  assert.ok(REPAIR_COMMAND.includes("git remote set-url origin"));
  assert.ok(REPAIR_COMMAND.includes("git fetch origin --prune"));
});
