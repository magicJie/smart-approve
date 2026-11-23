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
 * Patterns are per-argument: the command is tokenized with real shell
 * rules (quotes and backslash escapes group characters), then each
 * pattern token is glob-matched against the corresponding argument
 * VALUE.  `*`/`?` never cross `/`; `**` may — so `cat *` matches
 * `cat 'a file'` (one argument) but never `cat a b` (two arguments).
 * A positive pattern authorizes exactly one program — the whole command
 * must be that program and nothing else.  A leading `!` negates per
 * program: `!rm *` fails the match when ANY program in the compound is
 * `rm …` — a negated rule cannot be slipped past by appending another
 * command or piping through another stage.
 */
export function matchCommandGlob(pattern: string, value: string): boolean {
  let negate = false;
  let p = pattern.trim();
  if (p.startsWith("!")) { negate = true; p = p.slice(1).trim(); }
  if (p === "") return false;

  const patternTokens = roughTokenize(p);
  const argGlobs: (RegExp | null)[] = [];
  for (const token of patternTokens) {
    const re = compileArgGlob(unquoteToken(token));
    if (re === null) return false;
    argGlobs.push(re);
  }

  const programs = splitCommandSegments(value)
    .map((segment) => commandAndArgs(segment))
    .filter((invocation): invocation is CommandInvocation => invocation !== undefined);

  const matches = (invocation: CommandInvocation): boolean => {
    const program = [invocation.program, ...invocation.args];
    if (program.length !== argGlobs.length) return false;
    return argGlobs.every((re, i) => re!.test(program[i]));
  };

  if (negate) {
    // Any matching program anywhere in the compound fails the entry.
    return !programs.some(matches);
  }
  // Positive: the command must be exactly one matching program.
  return programs.length === 1 && matches(programs[0]);
}

/** Compile one pattern ARGUMENT to a regex.  `*`/`?` stay inside the
 *  argument and never cross `/`; `**` spans `/` too. */
function compileArgGlob(arg: string): RegExp | null {
  let re = "^";
  let i = 0;
  while (i < arg.length) {
    const c = arg[i];
    if (c === "*") {
      if (arg[i + 1] === "*") {
        re += ".*";
        i += 2;
      } else {
        re += "[^/]*";
        i += 1;
      }
    } else if (c === "?") {
      re += "[^/]";
      i += 1;
    } else if (".+()[]{}^$|\\".includes(c)) {
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
      // `>&` / `<&` fd duplications and `&>` / `&>>` combined redirects are
      // redirection syntax — not command separators.
      if (ch === "&" && (value[i - 1] === ">" || value[i - 1] === "<")) continue;
      if (ch === "&" && value[i + 1] === ">") continue;
      if (ch === "|" && value[i - 1] === ">") continue; // `>|` is redirection
      const segment = value.slice(start, i).trim();
      if (segment) result.push(segment);
      if (value[i + 1] === ch) i++;
      if (ch === "|" && value[i + 1] === "&") i++; // `|&` stderr pipe
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

// ── Shell tokenization (shared with behavior analysis and allow-list globs) ─

export interface CommandInvocation {
  /** Program token as invoked — path and case preserved (`/usr/bin/sort`,
   *  `CURL`).  `name` is the lowercased basename used for classification;
   *  authorization globs match on `program` (W1). */
  program: string;
  name: string;
  args: string[];
  /** Raw token text per arg: `'…'`-quoted operands are literal and must not
   *  get HOME/tilde expansion (R6). */
  rawArgs: string[];
}

/** Evaluate a complete shell word: quoted and unquoted fragments
 *  concatenate (`"2026".log` → `2026.log`), backslash escapes outside quotes
 *  unescape, double quotes unescape only `$`, `"`, `\\`, backtick.  Unlike
 *  unquoteToken (which only unwraps fully-quoted tokens), this handles mixed
 *  fragments — used for path operands where the evaluated value is the real
 *  filename (Y1). */
export function evaluateShellWord(raw: string): string {
  let out = "";
  let i = 0;
  while (i < raw.length) {
    const c = raw[i];
    if (c === "'") {
      i++;
      while (i < raw.length && raw[i] !== "'") out += raw[i++];
      i++; // closing quote
    } else if (c === '"') {
      i++;
      while (i < raw.length && raw[i] !== '"') {
        if (raw[i] === "\\" && i + 1 < raw.length && /["\\$`]/.test(raw[i + 1])) {
          out += raw[i + 1];
          i += 2;
        } else {
          out += raw[i++];
        }
      }
      i++; // closing quote
    } else if (c === "\\" && i + 1 < raw.length) {
      out += raw[i + 1];
      i += 2;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

export function unquoteToken(token: string): string {
  if (
    token.length >= 2 &&
    ((token[0] === "'" && token[token.length - 1] === "'") ||
      (token[0] === "\"" && token[token.length - 1] === "\""))
  ) {
    const inner = token.slice(1, -1);
    // Inside double quotes, backslash escapes ", \\, $, ` — unescape those.
    if (token[0] === "\"") {
      return inner.replace(/\\(["\\$`])/g, "$1");
    }
    return inner;
  }
  // Unquoted tokens still carry backslash escapes (\  → space etc.).
  return token.replace(/\\(.)/g, "$1");
}

export function isAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(unquoteToken(token));
}

export function roughTokenize(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: string | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote === "\"") {
      current += ch;
      if (ch === "\\" && i + 1 < command.length) {
        current += command[++i]; // \" stays inside the token
      } else if (ch === "\"") {
        quote = null;
      }
    } else if (quote === "'") {
      current += ch;
      if (ch === "'") quote = null;
    } else if (ch === "\\" && i + 1 < command.length) {
      // Backslash escapes the next character — it belongs to this token.
      current += ch + command[++i];
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
    } else if (/\s/.test(ch)) {
      if (current) { tokens.push(current); current = ""; }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);
  return tokens;
}

export function commandAndArgs(
  segment: string,
  options: { unwrapXargs?: boolean } = {},
): CommandInvocation | undefined {
  const tokens = roughTokenize(segment);
  let index = 0;

  while (index < tokens.length) {
    const token = unquoteToken(tokens[index]);
    const name = path.basename(token).toLowerCase();
    if (isAssignment(tokens[index]) || ["!", "if", "then", "do", "else", "elif"].includes(name)) {
      index++;
      continue;
    }
    if (name === "env") {
      index++;
      while (index < tokens.length) {
        const option = unquoteToken(tokens[index]);
        if (isAssignment(tokens[index])) {
          index++;
          continue;
        }
        if (option === "--") {
          index++;
          break;
        }
        if (!option.startsWith("-")) break;
        index++;
        if (["-u", "--unset", "-C", "--chdir"].includes(option) && index < tokens.length) index++;
      }
      continue;
    }
    if (name === "xargs" && options.unwrapXargs !== false) {
      index++;
      while (index < tokens.length) {
        const option = unquoteToken(tokens[index]);
        if (option === "--") {
          index++;
          break;
        }
        if (!option.startsWith("-")) break;
        index++;
        if (
          ["-E", "--eof", "-I", "--replace", "-L", "--max-lines", "-n", "--max-args",
            "-P", "--max-procs", "-s", "--max-chars", "-d", "--delimiter", "-a", "--arg-file"].includes(option) &&
          index < tokens.length
        ) {
          index++;
        }
      }
      continue;
    }
    if (["command", "exec", "nohup", "time", "setsid"].includes(name)) {
      index++;
      if (["command", "time"].includes(name) && tokens[index] === "-p") index++;
      if (name === "setsid" && tokens[index] === "-f") index++;
      if (tokens[index] === "--") index++;
      if (name === "exec" && tokens[index] === "-a") index += 2;
      continue;
    }
    if (name === "timeout") {
      index++;
      while (index < tokens.length && tokens[index].startsWith("-")) {
        const option = tokens[index++];
        if (["-k", "--kill-after", "-s", "--signal"].includes(option) && index < tokens.length) index++;
      }
      if (tokens[index] !== undefined) index++;
      continue;
    }
    if (name === "nice") {
      index++;
      if (tokens[index] === "-n") index += 2;
      else if (/^-n\d+$/.test(tokens[index] ?? "")) index++;
      continue;
    }
    return {
      program: unquoteToken(tokens[index]),
      name,
      args: tokens.slice(index + 1).map(unquoteToken),
      rawArgs: tokens.slice(index + 1),
    };
  }

  return undefined;
}

/** Expand the HOME forms resolvable without running the shell (~, $HOME,
 *  ${HOME}).  Any other $/`/glob/`~user` form is dynamic → undefined. */
export function expandHomeLiteral(value: string, home: string): string | undefined {
  let expanded = value;
  if (!expanded) return undefined;
  if (expanded === "~") expanded = home;
  else if (expanded.startsWith("~/")) {
    // Prefix substitution, NOT path.join: keep the original components
    // (incl. "..") so the realpath walk still sees them (V4).
    expanded = home + expanded.slice(1);
  }
  else if (expanded.startsWith("~")) return undefined; // ~user needs a lookup
  const placeholder = "\0HOME\0";
  expanded = expanded
    .replace(/\$\{HOME\}/g, placeholder)
    .replace(/\$HOME(?![A-Za-z0-9_])/g, placeholder);
  if (/[$`{}\[\]*?]/.test(expanded)) return undefined;
  return expanded.split(placeholder).join(home) || undefined;
}

/** Resolve a local path and its symlinked ancestors, including missing write targets.
 *  `expandHome:false` treats `~`/`$HOME` as ordinary characters — pass it when
 *  the caller already applied quoting-aware expansion (R6). */
export function resolveFilesystemPathCandidates(
  filePath: string,
  baseCwd = process.cwd(),
  options: { expandHome?: boolean } = {},
): string[] {
  if (!filePath) return [];
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(filePath)) return [filePath];

  const home = process.env.HOME || os.homedir();
  const expandHome = options.expandHome !== false;
  const expanded = !expandHome ? filePath
    : filePath === "~"
      ? home
      : filePath.startsWith("~/")
        ? home + filePath.slice(1) // keep ".." components for the realpath walk (V4)
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
 * realpath-semantics resolution: components resolve in order, so a `..`
 * after a symlinked directory escapes the link target, matching what the
 * filesystem actually does.  Falls back to the lexical candidate list when
 * the prefix doesn't exist.
 */
export function semanticPathCandidates(
  target: string,
  baseCwd: string,
  options: { expandHome?: boolean } = {},
): string[] {
  const lexical = resolveFilesystemPathCandidates(target, baseCwd, options);
  // The semantic walk must see the same expanded string the lexical pass
  // resolved — a raw `~`/`$HOME` prefix would otherwise produce a spurious
  // `cwd/~/…` candidate (W3).
  const home = process.env.HOME || os.homedir();
  const expandHome = options.expandHome !== false;
  const expandedTarget = !expandHome ? target
    : target === "~" ? home
    : target.startsWith("~/") ? home + target.slice(1) // keep ".." components (V4)
    : target;
  if (!path.isAbsolute(expandedTarget) && !path.isAbsolute(baseCwd)) return lexical;
  const absolute = path.isAbsolute(expandedTarget) ? expandedTarget : `${baseCwd}/${expandedTarget}`;
  // Original components (pre-`..` folding) so a `..` right after a symlinked
  // directory escapes the link target — realpath semantics (R3).
  const parts = absolute.split("/").filter((part) => part !== "" && part !== ".");
  let current = "/";
  let resolved = 0; // components of `parts` already folded into `current`
  for (const part of parts) {
    if (part === "..") {
      try {
        current = fs.realpathSync(path.dirname(current));
      } catch {
        current = path.dirname(current);
      }
      resolved++;
      continue;
    }
    try {
      current = fs.realpathSync(`${current}/${part}`);
      resolved++;
    } catch {
      break; // missing tail — the resolved prefix still holds
    }
  }
  if (resolved === 0) return lexical;
  const semantic = [current, ...parts.slice(resolved)].join("/");
  const lexicalAbsolute = lexical[0] ?? absolute;
  return semantic === lexicalAbsolute ? [lexicalAbsolute] : [lexicalAbsolute, semantic];
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

    // realpath-ordered resolution — a `..` right after a symlinked
    // directory must escape the link target before the pattern match (W3).
    for (const candidate of semanticPathCandidates(filePath, baseCwd)) {
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
