import assert from "node:assert/strict";
import { test } from "node:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { AllowList } from "./allowlist.ts";
import type { AllowEntry } from "./types.ts";

function makeList(entries: AllowEntry[]): { list: AllowList; dir: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-allow-"));
  const file = path.join(dir, "allow.json");
  fs.writeFileSync(file, JSON.stringify({ permanent: entries }), "utf-8");
  return { list: new AllowList(file), dir };
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

const CWD = "/work/project";

test("exact permanent match still wins before pattern and domain", () => {
  const { list, dir } = makeList([
    { tool: "bash", key: "chmod 600 ~/.draft", cwd: CWD, timestamp: "2026-01-01" },
  ]);
  try {
    assert.equal(list.isAllowed("bash", "chmod 600 ~/.draft", CWD), true);
    assert.equal(list.isAllowed("bash", "chmod 600 ~/.other", CWD), false);
    assert.equal(list.isAllowed("bash", "chmod 600 ~/.draft", "/other/cwd"), false);
  } finally {
    cleanup(dir);
  }
});

test("pattern entries match normalized commands by glob", () => {
  const { list, dir } = makeList([
    {
      tool: "bash",
      key: "chmod 600 ~/.draft",
      cwd: CWD,
      timestamp: "2026-01-01",
      pattern: "chmod * ~/.draft",
    },
    {
      tool: "bash",
      key: "git push -f origin feature",
      cwd: CWD,
      timestamp: "2026-01-01",
      pattern: "git push * origin feature",
    },
  ]);
  try {
    assert.equal(list.isAllowed("bash", "chmod 600 ~/.draft", CWD), true);
    assert.equal(list.isAllowed("bash", "chmod 755 ~/.draft", CWD), true);
    assert.equal(list.isAllowed("bash", "chmod 600 ~/.other", CWD), false);
    assert.equal(list.isAllowed("bash", "git push -f origin feature", CWD), true);
    assert.equal(list.isAllowed("bash", "git push -f origin main", CWD), false);
  } finally {
    cleanup(dir);
  }
});

test("domain entries require every path argument inside the domain", () => {
  const domain = "/home/jay/projects";
  const { list, dir } = makeList([
    {
      tool: "bash",
      key: "chmod 600 file",
      cwd: CWD,
      timestamp: "2026-01-01",
      domain,
    },
  ]);
  try {
    assert.equal(
      list.isAllowed("bash", "chmod 600 /home/jay/projects/app/secret.env", CWD),
      true,
    );
    assert.equal(
      list.isAllowed("bash", "chmod 600 /home/jay/projects/app/secret.env /home/jay/projects/b.txt", CWD),
      true,
    );
    // A path outside the domain defeats the scoped allow.
    assert.equal(
      list.isAllowed("bash", "chmod 600 /home/jay/projects/a /etc/passwd", CWD),
      false,
    );
    assert.equal(
      list.isAllowed("bash", "chmod 600 /var/log/app.log", CWD),
      false,
    );
    // No path-like argument: cwd must itself be inside the domain.
    assert.equal(list.isAllowed("bash", "npm run build", "/home/jay/projects/app"), true);
    assert.equal(list.isAllowed("bash", "npm run build", CWD), false);
  } finally {
    cleanup(dir);
  }
});

test("session tier is cwd-scoped and unaffected by pattern/domain", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-allow-"));
  const file = path.join(dir, "allow.json");
  try {
    const list = new AllowList(file);
    list.rememberSession("bash", "chmod 600 ~/.draft", CWD);
    assert.equal(list.isAllowed("bash", "chmod 600 ~/.draft", CWD), true);
    assert.equal(list.isAllowed("bash", "chmod 600 ~/.draft", "/other"), false);
  } finally {
    cleanup(dir);
  }
});
