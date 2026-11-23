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

// ── REVIEW B3: scoped entries enforce every constraint ────────────────

test("combined pattern+domain entries reject single-side matches", () => {
  const domain = "/home/jay/projects";
  const { list, dir } = makeList([
    {
      tool: "bash",
      key: "chmod 600 file",
      cwd: CWD,
      timestamp: "2026-01-01",
      pattern: "chmod ** /home/jay/projects/**",
      domain,
    },
  ]);
  try {
    // Both constraints satisfied → allowed.
    assert.equal(
      list.isAllowed("bash", "chmod 600 /home/jay/projects/app/secret.env", CWD),
      true,
    );
    // Pattern matches but the target escapes the domain → rejected.
    assert.equal(list.isAllowed("bash", "chmod 600 /etc/hosts", CWD), false);
    // Domain satisfied but the command is not chmod → rejected.
    assert.equal(list.isAllowed("bash", "rm /home/jay/projects/app/file", CWD), false);
  } finally {
    cleanup(dir);
  }
});

test("exact keys outside their scope are rejected", () => {
  const { list, dir } = makeList([
    {
      tool: "bash",
      key: "rm -rf /tmp/x",
      cwd: CWD,
      timestamp: "2026-01-01",
      pattern: "chmod **",
    },
  ]);
  try {
    // Key+cwd match exactly, but the command violates the pattern scope.
    assert.equal(list.isAllowed("bash", "rm -rf /tmp/x", CWD), false);
  } finally {
    cleanup(dir);
  }
});

test("command globs reject extra command segments and honor negation", () => {
  const { list, dir } = makeList([
    {
      tool: "bash",
      key: "chmod 600 file",
      cwd: CWD,
      timestamp: "2026-01-01",
      pattern: "chmod ** **",
    },
  ]);
  const { list: negated, dir: negatedDir } = makeList([
    {
      tool: "bash",
      key: "legacy",
      cwd: CWD,
      timestamp: "2026-01-01",
      pattern: "!rm *",
    },
  ]);
  try {
    // `**` spans a whole argument (incl. `/`) but never whitespace or
    // separators — compound commands can never satisfy it.
    assert.equal(list.isAllowed("bash", "chmod 600 file; rm -rf /tmp/x", CWD), false);
    assert.equal(list.isAllowed("bash", "chmod 600 file && ls", CWD), false);
    assert.equal(list.isAllowed("bash", "chmod 600 file", CWD), true);
    // `*` stays inside one argument and never crosses `/` or whitespace.
    const { list: singleStar, dir: singleDir } = makeList([
      {
        tool: "bash",
        key: "k",
        cwd: CWD,
        timestamp: "2026-01-01",
        pattern: "chmod *",
      },
    ]);
    try {
      assert.equal(singleStar.isAllowed("bash", "chmod 600", CWD), true);
      assert.equal(singleStar.isAllowed("bash", "chmod 600 file", CWD), false);
      assert.equal(singleStar.isAllowed("bash", "chmod a/x", CWD), false);
    } finally {
      cleanup(singleDir);
    }
    // Negated pattern: any `rm …` segment — even in a compound — fails.
    assert.equal(negated.isAllowed("bash", "rm file", CWD), false);
    assert.equal(negated.isAllowed("bash", "rm file; ls", CWD), false);
    assert.equal(negated.isAllowed("bash", "ls -la", CWD), true);
  } finally {
    cleanup(dir);
    cleanup(negatedDir);
  }
});

// ── REVIEW B4: full target extraction and realpath containment ────────

test("domain matching handles mixed targets, spaces, links, and cwd", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-domain-"));
  const domain = path.join(root, "domain");
  const outside = path.join(root, "outside");
  fs.mkdirSync(domain);
  fs.mkdirSync(outside);
  fs.mkdirSync(path.join(domain, "sub"));
  fs.writeFileSync(path.join(domain, "my file.txt"), "x");
  fs.writeFileSync(path.join(outside, "secret"), "x");
  fs.symlinkSync(path.join(outside, "secret"), path.join(domain, "escape"));
  const { list, dir } = makeList([
    {
      tool: "bash",
      key: "entry",
      cwd: CWD,
      timestamp: "2026-01-01",
      domain,
    },
  ]);
  try {
    // Mixed relative + absolute targets, all inside → allowed.
    assert.equal(
      list.isAllowed("bash", `cp file1 sub/file2 ${domain}/dest`, domain),
      true,
    );
    // Quoted filename with spaces resolves inside the domain.
    assert.equal(list.isAllowed("bash", 'chmod 600 "my file.txt"', domain), true);
    // One target outside the domain rejects the whole command.
    assert.equal(list.isAllowed("bash", `cp file1 ${outside}/secret ${domain}/d`, domain), false);
    // In-domain symlink pointing outside fails canonical containment.
    assert.equal(list.isAllowed("bash", "chmod 600 escape", domain), false);
    // Same relative command resolves differently per execution cwd.
    // Unquoted spaces split into two targets, both still in-domain.
    assert.equal(list.isAllowed("bash", "chmod 600 my file.txt", domain), true);
    assert.equal(list.isAllowed("bash", "chmod 600 secret", outside), false);
    // Dynamic targets cannot be proven in-domain → normal approval.
    assert.equal(list.isAllowed("bash", "chmod 600 $UNKNOWN_VAR/file", domain), false);
  } finally {
    cleanup(dir);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ── Suggestion: permanent entries persist exact shape ─────────────────

test("rememberPermanent writes exact tool/key/cwd/timestamp entries", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-allow-"));
  const file = path.join(dir, "allow.json");
  try {
    const list = new AllowList(file);
    list.rememberPermanent("bash", "chmod 600 ~/.draft", CWD);
    const stored = JSON.parse(fs.readFileSync(file, "utf-8"));
    assert.equal(stored.permanent.length, 1);
    const entry = stored.permanent[0];
    assert.deepEqual(Object.keys(entry).sort(), ["cwd", "key", "timestamp", "tool"]);
    assert.equal(entry.tool, "bash");
    assert.equal(entry.key, "chmod 600 ~/.draft");
    assert.equal(entry.cwd, CWD);
    assert.equal(typeof entry.timestamp, "string");
  } finally {
    cleanup(dir);
  }
});

test("domain entries see sort/git file targets and reject out-of-domain operands", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-sortdom-"));
  const domain = path.join(root, "domain");
  const outside = path.join(root, "outside");
  try {
    fs.mkdirSync(domain); fs.mkdirSync(outside);
    const { list } = makeList([
      { tool: "bash", key: "sort", cwd: root, timestamp: "t", domain },
    ]);
    // sort input+output in-domain → allowed.
    assert.equal(
      list.isAllowed("bash", `sort -o ${domain}/out.tsv ${domain}/in.tsv`, root),
      true,
    );
    // sort operand outside the domain → domain check fails → not allowed.
    assert.equal(
      list.isAllowed("bash", `sort -o ${domain}/out.tsv ${outside}/in.tsv`, root),
      false,
    );
    // git -C outside the domain → not allowed.
    assert.equal(list.isAllowed("bash", `git -C ${outside} status`, root), false);
    assert.equal(list.isAllowed("bash", `git -C ${domain} status`, root), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("domain check resolves .. through symlinks like the filesystem does", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-semdom-"));
  const domain = path.join(root, "a");
  try {
    fs.mkdirSync(domain);
    fs.writeFileSync(path.join(domain, "note"), "A");
    fs.writeFileSync(path.join(root, "note"), "B");
    fs.symlinkSync("/etc", path.join(domain, "l"));
    const { list } = makeList([
      { tool: "bash", key: "cat", cwd: domain, timestamp: "t", domain },
    ]);
    // Realpath semantics: l → /etc, .. → / — the open file is /note,
    // OUTSIDE the domain.  Lexical folding would answer a/note (inside).
    assert.equal(
      list.isAllowed("bash", "cat l/../note", domain),
      false,
      "domain must use realpath-ordered resolution",
    );
    // A link staying inside the domain keeps working.
    fs.symlinkSync(domain, path.join(domain, "self"));
    assert.equal(list.isAllowed("bash", "cat self/note", domain), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
