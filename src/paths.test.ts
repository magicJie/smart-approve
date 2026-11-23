import assert from "node:assert/strict";
import { test } from "node:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ProtectedPathMatcher, isUserWritablePath } from "./paths.ts";

test("protected relative paths resolve from the session working directory", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-paths-"));
  try {
    const matcher = new ProtectedPathMatcher(["**/.aws/credentials"]);
    assert.equal(matcher.isProtected("nested/.aws/credentials", cwd), true);
    assert.equal(matcher.isProtected("nested/.aws/config", cwd), false);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test("isUserWritablePath only accepts home or session-cwd targets", () => {
  const home = process.env.HOME || os.homedir();
  const session = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-userpath-"));
  try {
    assert.equal(isUserWritablePath("~/.draft", session, home), true);
    assert.equal(isUserWritablePath(`${home}/file.txt`, session, home), true);
    assert.equal(isUserWritablePath("./dir", session, home), true);
    assert.equal(isUserWritablePath("subdir/file", session, home), true);
    assert.equal(isUserWritablePath("/etc/passwd", session, home), false);
    assert.equal(isUserWritablePath("/opt/thing", session, home), false);
    assert.equal(isUserWritablePath("/tmp/scratch", session, home), false);
    assert.equal(isUserWritablePath("", session, home), false);
    // The home root itself is inside home — callers distinguish it separately.
    assert.equal(isUserWritablePath(home, session, home), true);
  } finally {
    fs.rmSync(session, { recursive: true, force: true });
  }
});
