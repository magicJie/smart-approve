/**
 * Smart Approve — protected-path matcher.
 *
 * Glob-based matching against sensitive file paths.  Symlink-aware:
 * resolves realpath before matching so a symlink alias can't evade a deny.
 * Encapsulated as a class so patterns can be swapped per-config without
 * recompiling the glob converter.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** Default protected path patterns. */
export const DEFAULT_PROTECTED_PATHS: string[] = [
  ".env",
  ".env.*",
  "!.env.example",          // allow .env.example
  "**/.ssh/**",
  "**/.ssh/*",
  "**/.kube/config",
  "**/.aws/credentials",
  "**/.aws/config",
  "**/.config/gh/hosts.yml",
  "**/.config/gcloud/**",
  "**/.git-credentials",
  "**/.netrc",
  "**/.npmrc",
  "**/.pypirc",
  "**/id_rsa",
  "**/id_ed25519",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.kdbx",
  "**/auth.json",
];

interface CompiledPattern {
  re: RegExp;
  negate: boolean;
}

function isWithinDirectory(candidate: string, directory: string): boolean {
  return candidate === directory ||
    candidate.startsWith(directory === path.sep ? path.sep : `${directory}${path.sep}`);
}

/** Convert a glob pattern to a RegExp. Supports **, *, negation prefix. */
function globToRegExp(pattern: string): CompiledPattern {
  let negate = false;
  let p = pattern;
  if (p.startsWith("!")) { negate = true; p = p.slice(1); }

  let re = "";
  let i = 0;
  while (i < p.length) {
    const c = p[i];
    if (c === "*") {
      if (p[i + 1] === "*") {
        re += ".*";
        i += 2;
        if (p[i] === "/") i++;
      } else {
        re += "[^/]*";
        i += 1;
      }
    } else if (c === "?") {
      re += "[^/]";
      i += 1;
    } else if (c === ".") {
      re += "\\.";
      i += 1;
    } else if ("+()[]{}^$|".includes(c)) {
      re += "\\" + c;
      i += 1;
    } else {
      re += c;
      i += 1;
    }
  }
  return { re: new RegExp(re + "$"), negate };
}

/**
 * Test a normalized command against a command glob (R5).
 * Positive patterns must match the FULL command: `*`/`?` stay inside one
 * argument and never cross `/`, whitespace, or separators; `**` spans
 * directory separators but still stops at whitespace and command
 * separators — so `chmod * /projects/**` is a three-token pattern.
 * A leading `!` negates per command segment: `!rm *` fails the match when
 * ANY segment of a compound command is `rm …` — a negated rule cannot be
 * slipped past by appending another command.
 */
export function matchCommandGlob(pattern: string, value: string): boolean {
  let negate = false;
  let p = pattern.trim();
  if (p.startsWith("!")) { negate = true; p = p.slice(1); }
  if (p === "") return false;

  const re = compileCommandGlob(p);
  if (re === null) return false;
  if (!negate) return re.test(value);
  // Negation applies to each command segment of the compound input: any
  // segment matching the positive pattern makes the whole entry fail.
  for (const segment of splitCommandSegments(value)) {
    if (re.test(segment)) return false;
  }
  return true;
}

/** Segment boundary characters (unquoted `;` `&` `|` newline parens
 *  and subshell/redirection syntax) for both glob classes and splitting. */
const GLOB_SEPARATOR = String.raw`\s;&|()<>` + "`";

function compileCommandGlob(pattern: string): RegExp | null {
  let re = "^";
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        // `**`: within one argument, may cross `/`.
        re += `[^${GLOB_SEPARATOR}\\n]*`;
        i += 2;
      } else {
        // `*`: within one argument segment, no `/` crossing.
        re += `[^/${GLOB_SEPARATOR}\\n]*`;
        i += 1;
      }
    } else if (c === "?") {
      re += `[^/${GLOB_SEPARATOR}\\n]`;
      i += 1;
    } else if (".+()[]{}^$|".includes(c)) {
      re += "\\" + c;
      i += 1;
    } else {
      re += c;
      i += 1;
    }
  }
  try {
    return new RegExp(re + "$");
  } catch {
    return null;
  }
}

/** Quote- and escape-aware segment split for negation scoping. */
function splitCommandSegments(value: string): string[] {
  const result: string[] = [];
  let start = 0;
  let quote: string | undefined;
  let escaped = false;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (escaped) { escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === "\"" || ch === "`") { quote = ch; continue; }
    if (ch === ";" || ch === "\n" || ch === "(" || ch === ")") {
      const segment = value.slice(start, i).trim();
      if (segment) result.push(segment);
      start = i + 1;
      continue;
    }
    if (ch === "&" || (ch === "|")) {
      const segment = value.slice(start, i).trim();
      if (segment) result.push(segment);
      if (value[i + 1] === ch) i++;
      start = i + 1;
    }
  }
  const tail = value.slice(start).trim();
  if (tail) result.push(tail);
  return result;
}

/**
 * True when `target` resolves inside the user's home or the session cwd —
 * i.e. the paths a user-level task may legitimately modify.  Symlink-aware:
 * every lexical + canonical candidate must land inside a user-writable root,
 * so an in-domain symlink pointing outside still fails.
 * Returns false for empty targets, URLs, and out-of-domain absolute paths.
 */
export function isUserWritablePath(
  target: string,
  sessionCwd: string,
  home = process.env.HOME || os.homedir(),
): boolean {
  if (!target) return false;
  const candidates = resolveFilesystemPathCandidates(target, sessionCwd);
  if (candidates.length === 0) return false;
  const homeCandidates = resolveFilesystemPathCandidates(home, home);
  const sessionCandidates = resolveFilesystemPathCandidates(sessionCwd, sessionCwd);
  return candidates.every((candidate) =>
    homeCandidates.some((directory) => isWithinDirectory(candidate, directory)) ||
    sessionCandidates.some((directory) => isWithinDirectory(candidate, directory)),
  );
}

/** Resolve a local path and its symlinked ancestors, including missing write targets. */
export function resolveFilesystemPathCandidates(
  filePath: string,
  baseCwd = process.cwd(),
): string[] {
  if (!filePath) return [];
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(filePath)) return [filePath];

  const home = process.env.HOME || os.homedir();
  const expanded = filePath === "~"
    ? home
    : filePath.startsWith("~/")
      ? path.join(home, filePath.slice(2))
      : filePath;
  const absolutePath = path.resolve(baseCwd, expanded);
  const missingSegments: string[] = [];
  let ancestor = absolutePath;
  let resolvedPath = absolutePath;

  while (true) {
    try {
      resolvedPath = path.resolve(fs.realpathSync(ancestor), ...missingSegments);
      break;
    } catch {
      const parent = path.dirname(ancestor);
      if (parent === ancestor) break;
      missingSegments.unshift(path.basename(ancestor));
      ancestor = parent;
    }
  }

  return resolvedPath === absolutePath ? [absolutePath] : [absolutePath, resolvedPath];
}

/**
 * Glob matcher for protected paths.
 * Stateless after construction; safe to call concurrently.
 */
export class ProtectedPathMatcher {
  private readonly patterns: string[];
  private readonly compiled: CompiledPattern[];

  constructor(patterns: string[] = DEFAULT_PROTECTED_PATHS) {
    this.patterns = patterns;
    this.compiled = patterns.map(globToRegExp);
  }

  /** Check if a path matches any protected pattern, including symlinked parents. */
  isProtected(filePath: string, baseCwd = process.cwd()): boolean {
    if (!filePath || this.patterns.length === 0) return false;

    for (const candidate of resolveFilesystemPathCandidates(filePath, baseCwd)) {
      const normalized = candidate.replace(/\\/g, "/");
      const basename = path.basename(candidate);

      let matched = false;
      for (const { re, negate } of this.compiled) {
        if (re.test(normalized) || re.test(basename)) {
          matched = !negate;
        }
      }
      if (matched) return true;
    }
    return false;
  }
}
