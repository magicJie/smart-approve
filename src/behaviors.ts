/**
 * Smart Approve — behavior detection.
 *
 * Behavior-based detection parses executable positions, arguments, and
 * filesystem targets so text in messages or output is not treated as code.
 * Only shell-grammar constructs such as fork bombs and code piped to an
 * interpreter use syntax patterns; substitutions are analyzed separately.
 */

import type { DangerAnalysis } from "./types";
import { makeLabel } from "./i18n";
import { resolveFilesystemPathCandidates, semanticPathCandidates } from "./paths";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";

// ── Behavior catalog ─────────────────────────────────────────────────

const BEHAVIORS: Record<string, { en: string; zh: string }> = {
  "recursive-force-delete": makeLabel("Recursive force delete (rm -rf)", "递归强制删除 rm -rf"),
  "delete-root": makeLabel("Delete root path /", "删除根路径 /"),
  "delete-sys-dir": makeLabel("Delete system directory", "删除系统目录"),
  "fork-bomb": makeLabel("Fork bomb", "Fork bomb"),
  "remote-fetch-exec": makeLabel("Remote fetch-and-execute (curl|sh)", "远程拉取即执行 (curl|sh)"),
  "write-sensitive-file": makeLabel("Write to system-sensitive file", "写系统敏感文件"),
  "write-block-device": makeLabel("Write to raw block device", "写裸块设备"),
  "chmod-sys-dir": makeLabel("Change system directory permissions", "改系统目录权限"),
  "shutdown-reboot": makeLabel("Shutdown / reboot", "关机/重启"),
  "disk-format": makeLabel("Disk format / raw write", "格式化/裸写块设备"),
  "mount-block-device": makeLabel("Mount / unmount block device", "挂载/卸载块设备"),
  "force-kill": makeLabel("Force kill process (SIGKILL)", "强杀进程 SIGKILL"),
  "pkg-global-uninstall": makeLabel("Global package uninstall", "全局卸载包"),
  "git-force-push": makeLabel("git force / mirror push", "git 强制/镜像推送"),
  "git-push-delete": makeLabel("git push --delete (remote ref)", "git push --delete 删远程引用"),
  "git-push-colon-ref": makeLabel("git push :ref (delete remote branch)", "git push :ref 删远程分支"),
  "git-hard-reset": makeLabel("git reset --hard (discard changes)", "git reset --hard 丢弃改动"),
  "git-clean": makeLabel("git clean -f (delete untracked)", "git clean -f 删未跟踪文件"),
  "git-branch-delete": makeLabel(
    "git branch -d/-D (delete local branch)",
    "git branch -d/-D 删除本地分支",
  ),
  "git-branch-delete-remote": makeLabel(
    "git branch -r -d (delete remote-tracking branch)",
    "git branch -r -d 删远程跟踪分支",
  ),
  "git-tag-delete": makeLabel("git tag -d (delete tag)", "git tag -d 删标签"),
  "git-stash-clear": makeLabel("git stash clear", "git stash clear 清空 stash"),
  "git-stash-drop": makeLabel("git stash drop", "git stash drop 丢 stash"),
  "git-reflog-expire": makeLabel("git reflog expire", "git reflog expire 清引用日志"),
  "git-gc-prune": makeLabel("git gc --prune (purge objects)", "git gc --prune 清理对象"),
  "git-filter-branch": makeLabel("git filter-branch (rewrite history)", "git filter-branch 重写历史"),
  "git-filter-repo": makeLabel("git filter-repo (rewrite history)", "git filter-repo 重写历史"),
  "git-commit-amend": makeLabel("git commit --amend", "git commit --amend 修订提交"),
  "git-rebase": makeLabel("git rebase (rewrite history)", "git rebase 重写历史"),
  "git-remote-rm": makeLabel("git remote rm", "git remote rm 移除远程"),
  "git-submodule-deinit": makeLabel("git submodule deinit", "git submodule deinit"),
  "git-worktree-remove": makeLabel("git worktree remove", "git worktree remove"),
  "git-update-ref-delete": makeLabel("git update-ref -d (delete ref)", "git update-ref -d 删引用"),
  "git-checkout-discard": makeLabel("git checkout -- . (discard all)", "git checkout -- . 丢所有改动"),
  "git-restore-discard": makeLabel("git restore . (discard worktree)", "git restore . 丢工作区改动"),
  "git-config-global": makeLabel("git config --global", "git config --global 改全局配置"),
  "git-notes-remove": makeLabel("git notes remove", "git notes remove 删 notes"),
  "docker-destroy": makeLabel("docker rm/rmi/volume/network rm", "docker 删除容器/镜像/卷"),
  "kubectl-delete": makeLabel("kubectl delete", "kubectl delete"),
  "mv-sys-dir": makeLabel("Move system directory", "移动系统目录"),
  "cp-root": makeLabel("Recursive copy to root", "递归拷贝到根"),
  "git-force-push-protected": makeLabel("git force push to protected branch", "git 强制推送到保护分支"),
  "delete-home": makeLabel("Delete home directory (~)", "删除家目录 ~"),
  "high-risk-executable": makeLabel("High-risk process launch", "启动高风险程序"),
  "high-risk-net-tool": makeLabel("Network / crypto utility launch", "启动网络/加密工具"),
  "high-risk-shell-pivot": makeLabel("Raw network pivot tool (reverse-shell class)", "启动裸网络枢轴工具（反弹 Shell 类）"),
  "privileged-exec": makeLabel("Privileged execution (sudo/ssh/scp/osascript)", "提权执行 sudo/ssh/scp/osascript"),
  "interpreter-inline-execution": makeLabel("Interpreter executes inline code", "解释器执行内联代码"),
  "permission-change": makeLabel("Changes file permissions or ownership", "修改文件权限或所有者"),
  "permission-change-system": makeLabel("Changes system path permissions or other-user ownership", "修改系统路径权限或改其他用户属主"),
  "permission-change-user": makeLabel("Changes permissions on user-writable paths", "修改用户可写路径的权限"),
  "dd-block-device": makeLabel("dd writes directly to a block device", "dd 直接写入块设备"),
  "dd-write": makeLabel("Writes data to a file with dd", "使用 dd 写入文件"),
  "sensitive-file-reference": makeLabel("Access to protected system account files", "访问受保护的系统账号文件"),
  "sensitive-working-directory": makeLabel("Runs outside the session in a sensitive directory", "在会话目录外的敏感目录运行"),
};

// Regexes over arbitrary arguments caused false positives in commit messages
// and other data. Retain only this shell-grammar signature; command families
// are matched from parsed executable names and arguments below.
const FORK_BOMB_PATTERN = /(?:^|[;&|])\s*:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;
/** Reviewable: common AI-task network and crypto tools. */
const HIGH_RISK_NET_TOOLS: Record<string, true> = {
  openssl: true,
  curl: true,
  wget: true,
};

/** Hard block: raw network primitives; reverse-shell toolkit with almost no
 *  legitimate use in AI tasks. */
const HIGH_RISK_SHELL_PIVOTS: Record<string, true> = {
  nc: true,
  netcat: true,
  ncat: true,
  socat: true,
  telnet: true,
};

/** Reviewable: privilege-escalation / remote-execution entry points. */
const PRIVILEGED_EXECS: Record<string, true> = {
  osascript: true,
  sudo: true,
  ssh: true,
  scp: true,
};

const INTERPRETERS: Record<string, true> = {
  sh: true, bash: true, zsh: true, dash: true, csh: true, tcsh: true, ksh: true, fish: true,
  node: true, nodejs: true, bun: true, deno: true, ruby: true, perl: true, php: true,
  lua: true, tclsh: true, expect: true,
};

function unquoteToken(token: string): string {
  if (
    token.length >= 2 &&
    ((token[0] === "'" && token[token.length - 1] === "'") ||
      (token[0] === "\"" && token[token.length - 1] === "\""))
  ) {
    return token.slice(1, -1);
  }
  return token;
}

function isAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(unquoteToken(token));
}
/** Remove shell comments without treating `#` inside quotes as a comment. */
function stripShellComments(command: string): string {
  let result = "";
  let quote: string | undefined;
  let escaped = false;
  let comment = false;

  for (let index = 0; index < command.length; index++) {
    const ch = command[index];
    if (comment) {
      if (ch === "\n") {
        result += ch;
        comment = false;
      } else {
        result += " ";
      }
      continue;
    }
    if (quote !== undefined) {
      result += ch;
      if (escaped) escaped = false;
      else if (ch === "\\" && quote !== "'") escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === "\"" || ch === "`") {
      quote = ch;
      result += ch;
      continue;
    }
    if (
      ch === "#" &&
      (index === 0 || /[\s;&|]/.test(command[index - 1]))
    ) {
      comment = true;
      result += " ";
      continue;
    }
    result += ch;
  }
  return result;
}

/** Remove quoted data before applying regex rules that describe shell syntax.
 *  Keep double-quoted command substitutions and backticks: they execute code. */
function stripQuotedShellData(command: string): string {
  const source = stripShellComments(command);
  let result = "";
  for (let index = 0; index < source.length; index++) {
    const quote = source[index];
    if (quote !== "'" && quote !== "\"") {
      result += quote;
      continue;
    }
    let cursor = index + 1;
    let escaped = false;
    while (cursor < source.length) {
      const ch = source[cursor];
      if (escaped) escaped = false;
      else if (quote === "\"" && ch === "\\") escaped = true;
      else if (ch === quote) break;
      cursor++;
    }
    const contents = source.slice(index + 1, cursor);
    const executesSubstitution = quote === "\"" && /(?:\$\(|`)/.test(contents);
    const literal = source.slice(index, Math.min(cursor + 1, source.length));
    result += executesSubstitution
      ? literal
      : literal.replace(/[^\n]/g, " ");
    index = cursor;
  }
  return result;
}
interface ShellSubstitution {
  start: number;
  end: number;
  body: string;
}

function findClosingParenthesis(source: string, open: number): number {
  let depth = 1;
  let quote: string | undefined;
  let escaped = false;

  for (let index = open + 1; index < source.length; index++) {
    const ch = source[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === "\"" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")" && --depth === 0) return index;
  }
  return -1;
}

function findClosingBacktick(source: string, start: number): number {
  for (let index = start + 1; index < source.length; index++) {
    if (source[index] === "\\") {
      index++;
      continue;
    }
    if (source[index] === "`") return index;
  }
  return -1;
}

/** Find executable substitutions, including those inside double quotes. */
function findShellSubstitutions(source: string): ShellSubstitution[] {
  const substitutions: ShellSubstitution[] = [];
  let quote: string | undefined;
  let escaped = false;

  for (let index = 0; index < source.length; index++) {
    const ch = source[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === "'") {
      if (ch === "'") quote = undefined;
      continue;
    }
    if (quote === "\"") {
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === "\"") {
        quote = undefined;
        continue;
      }
    } else if (ch === "\\") {
      escaped = true;
      continue;
    } else if (ch === "'") {
      quote = "'";
      continue;
    } else if (ch === "\"") {
      quote = "\"";
      continue;
    }

    if (ch === "`") {
      const closing = findClosingBacktick(source, index);
      if (closing >= 0) {
        substitutions.push({
          start: index,
          end: closing + 1,
          body: source.slice(index + 1, closing),
        });
        index = closing;
      }
      continue;
    }

    const processSubstitution =
      quote !== "\"" && (ch === "<" || ch === ">") && source[index + 1] === "(";
    const commandSubstitution = ch === "$" && source[index + 1] === "(";
    if (!processSubstitution && !commandSubstitution) continue;

    const open = index + 1;
    const closing = findClosingParenthesis(source, open);
    if (closing < 0) continue;
    substitutions.push({
      start: index,
      end: closing + 1,
      body: source.slice(open + 1, closing),
    });
    index = closing;
  }
  return substitutions;
}

function stripShellSubstitutions(
  command: string,
  substitutions: ShellSubstitution[],
): string {
  if (substitutions.length === 0) return command;
  let result = "";
  let cursor = 0;
  for (const substitution of substitutions) {
    result += command.slice(cursor, substitution.start);
    result += " ".repeat(substitution.end - substitution.start);
    cursor = substitution.end;
  }
  return result + command.slice(cursor);
}



function commandAndArgs(
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
      name,
      args: tokens.slice(index + 1).map(unquoteToken),
      rawArgs: tokens.slice(index + 1),
    };
  }

  return undefined;
}

function findExecCommands(args: string[]): string[][] {
  const commands: string[][] = [];
  for (let index = 0; index < args.length; index++) {
    if (!["-exec", "-execdir", "-ok", "-okdir"].includes(args[index])) continue;
    const start = index + 1;
    let end = start;
    while (
      end < args.length &&
      args[end] !== ";" &&
      args[end] !== "\\;" &&
      !(args[end] === "+" && (end === args.length - 1 || args[end + 1].startsWith("-")))
    ) {
      end++;
    }
    if (end > start) commands.push(args.slice(start, end));
    index = end;
  }
  return commands;
}

/** Quote one argv element as a single-quoted shell token.  Shared with the
 *  eval analyzer so argv-array spawns keep their argument boundaries (R4). */
export function quoteShellArgument(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

function hasRecursiveForceFlags(args: string[]): boolean {
  let recursive = false;
  let force = false;
  for (const arg of args) {
    if (arg === "--") break;
    if (arg === "--recursive") recursive = true;
    else if (arg === "--force") force = true;
    else if (/^-[^-]+$/.test(arg)) {
      const flags = arg.slice(1).toLowerCase();
      recursive ||= flags.includes("r");
      force ||= flags.includes("f");
    }
  }
  return recursive && force;
}

function isSensitiveAccountFilePath(value: string): boolean {
  return /(?:^|\/)etc\/(?:passwd|shadow|sudoers)(?:$|[./])/i.test(value);
}

function isGitMessageArgument(args: string[], index: number): boolean {
  const subcommand = skipGitGlobalOptions(args)?.subcommand;
  if (!["commit", "tag", "notes"].includes(subcommand ?? "")) return false;
  const value = args[index];
  return (
    args[index - 1] === "-m" ||
    args[index - 1] === "--message" ||
    value.startsWith("--message=") ||
    (value.startsWith("-m") && !value.startsWith("--"))
  );
}

function findGrepTextArguments(args: string[]): Set<number> {
  const textArguments = new Set<number>();
  let explicitPattern = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--") {
      if (!explicitPattern && args[index + 1] !== undefined) textArguments.add(index + 1);
      break;
    }
    if (arg === "-e" || arg === "--regexp") {
      explicitPattern = true;
      if (args[index + 1] !== undefined) textArguments.add(++index);
      continue;
    }
    if (
      arg.startsWith("--regexp=") ||
      arg.startsWith("--glob=") ||
      arg.startsWith("--iglob=") ||
      arg.startsWith("--include=") ||
      arg.startsWith("--exclude=") ||
      arg.startsWith("--exclude-dir=") ||
      arg.startsWith("--type=") ||
      arg.startsWith("--max-count=") ||
      (arg.startsWith("-e") && !arg.startsWith("--") && arg.length > 2) ||
      /^-g.+/.test(arg) ||
      /^-t.+/.test(arg)
    ) {
      if (
        arg.startsWith("--regexp=") ||
        (arg.startsWith("-e") && !arg.startsWith("--") && arg.length > 2)
      ) {
        explicitPattern = true;
      }
      textArguments.add(index);
      continue;
    }
    if (arg === "--exclude-from" && args[index + 1] !== undefined) {
      index++;
      continue;
    }
    if (arg.startsWith("-")) {
      if (
        ["-A", "-B", "-C", "-d", "-g", "-m", "-t", "--after-context", "--before-context", "--context",
          "--directories", "--exclude", "--exclude-dir", "--glob", "--iglob",
          "--include", "--label", "--max-count", "--sort", "--sortr", "--threads", "--type",
          "--type-add"].includes(arg) &&
        args[index + 1] !== undefined
      ) {
        textArguments.add(index + 1);
        index++;
      } else if (["-f", "--file"].includes(arg) && args[index + 1] !== undefined) {
        index++;
      }
      continue;
    }
    if (!explicitPattern) textArguments.add(index);
    break;
  }
  return textArguments;
}

function findSedScriptArguments(args: string[]): Set<number> {
  const scripts = new Set<number>();
  let foundScript = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "-e" || arg === "--expression") {
      foundScript = true;
      if (args[index + 1] !== undefined) scripts.add(++index);
    } else if (arg.startsWith("--expression=") || (arg.startsWith("-e") && arg.length > 2)) {
      foundScript = true;
      scripts.add(index);
    } else if (arg === "-f" || arg === "--file") {
      if (args[index + 1] !== undefined) index++;
    } else if (arg.startsWith("-")) {
      continue;
    } else if (!foundScript) {
      foundScript = true;
      scripts.add(index);
    }
  }
  return scripts;
}

function findAwkTextArguments(args: string[]): Set<number> {
  const textArguments = new Set<number>();
  let foundProgram = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (["-v", "--assign", "-F"].includes(arg)) {
      if (args[index + 1] !== undefined) textArguments.add(++index);
    } else if (/^-(?:v|F).+/.test(arg)) {
      textArguments.add(index);
    } else if (arg === "-f" || arg === "--file") {
      if (args[index + 1] !== undefined) index++;
    } else if (arg.startsWith("-")) {
      continue;
    } else if (!foundProgram) {
      foundProgram = true;
      textArguments.add(index);
    }
  }
  return textArguments;
}

function isSearchTextArgument(name: string, args: string[], index: number): boolean {
  if (["grep", "egrep", "fgrep", "rg", "ripgrep"].includes(name)) {
    return findGrepTextArguments(args).has(index);
  }
  if (name === "sed") return findSedScriptArguments(args).has(index);
  if (name === "awk" || name === "gawk") return findAwkTextArguments(args).has(index);
  if (name !== "git") return false;

  const command = skipGitGlobalOptions(args);
  if (!command) return false;
  const argumentIndex = index - (args.length - command.rest.length);
  if (argumentIndex < 0 || argumentIndex >= command.rest.length) return false;
  if (command.subcommand === "grep") {
    return findGrepTextArguments(command.rest).has(argumentIndex);
  }
  if (command.subcommand !== "log" && command.subcommand !== "show") return false;
  const arg = command.rest[argumentIndex];
  return (
    arg.startsWith("--grep=") ||
    arg.startsWith("--author=") ||
    arg.startsWith("--committer=") ||
    /^-[SG].+/.test(arg) ||
    ["--grep", "--author", "--committer", "-S", "-G"].includes(command.rest[argumentIndex - 1] ?? "")
  );
}

function hasSensitiveAccountFileReference(name: string, args: string[]): boolean {
  if (name === "echo" || name === "printf") return false;
  return args.some((value, index) =>
    isSensitiveAccountFilePath(value) &&
    !(name === "git" && isGitMessageArgument(args, index)) &&
    !isSearchTextArgument(name, args, index),
  );
}



/** Raw redirection targets per stage — the token is returned verbatim
 *  (quotes intact) so the caller can honor literal quoting via pathArg (R6). */
function redirectionTargets(segment: string): string[] {
  const targets: string[] = [];
  let quote: string | undefined;
  let escaped = false;

  for (let index = 0; index < segment.length; index++) {
    const ch = segment[index];
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (ch === "\\" && quote === "\"") escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "\\" ) {
      index++;
      continue;
    }
    if (ch === "'" || ch === "\"") {
      quote = ch;
      continue;
    }
    if (ch !== ">") continue;

    let cursor = index + 1;
    if (segment[cursor] === ">") cursor++;
    while (/\s/.test(segment[cursor] ?? "")) cursor++;
    if (segment[cursor] === "&" || segment[cursor] === "|") continue;

    const start = cursor;
    const targetQuote = segment[cursor];
    if (targetQuote === "'" || targetQuote === "\"") {
      cursor++;
      while (cursor < segment.length && segment[cursor] !== targetQuote) {
        if (segment[cursor] === "\\" && targetQuote === "\"" && cursor + 1 < segment.length) cursor++;
        cursor++;
      }
      if (segment[cursor] === targetQuote) cursor++;
    } else {
      while (cursor < segment.length && !/[\s;&|()<>\n]/.test(segment[cursor])) {
        cursor++;
      }
    }
    const target = segment.slice(start, cursor);
    if (target) targets.push(target);
    index = cursor - 1;
  }
  return targets;
}

function hasInterpreterExecutionFlag(args: string[]): boolean {
  return args.some((arg) =>
    arg === "-c" ||
    arg === "-e" ||
    arg === "-i" ||
    arg === "--eval" ||
    arg === "--command" ||
    /^-[^-]*[cei]/.test(arg) ||
    /^(?:--eval|--command)=/.test(arg),
  );
}

const SENSITIVE_DIRS = [
  "/etc", "/usr", "/var", "/bin", "/sbin", "/boot", "/Library", "/System", "/private",
];
const TEMPORARY_DIRS = [
  "/tmp",
  "/private/tmp",
  "/var/tmp",
  "/private/var/tmp",
  "/var/folders",
  "/private/var/folders",
];

function isWithinDirectory(candidate: string, directory: string): boolean {
  return candidate === directory ||
    candidate.startsWith(directory === path.sep ? path.sep : `${directory}${path.sep}`);
}

/**
 * Permission-change hard-block scope (DESIGN §3.3/§4.2):
 *  - resolved targets under system directories or the root dir itself are
 *    `permission-change-system`;
 *  - chmod/chown of the home root itself is `permission-change-system`;
 *  - chown whose OWNER differs from the current user is `permission-change-system`;
 *  - everything else is `permission-change-user` (reviewable — LLM judges).
 */
const PERMISSION_SYSTEM_PATH_RE =
  /^\/(?:etc|usr|bin|sbin|var|boot|sys|proc|root|Library|System)(?:\/|$)/i;

/** Block devices as operand values (shared with redirection checks). */
const BLOCK_DEVICE_PATH_RE =
  /^\/dev\/(?:sd[a-z]\d*|nvme\d+(?:n\d+)?(?:p\d+)?|disk\d+(?:s\d+)?|hd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*|mmcblk\d+(?:p\d+)?|mapper\/[^/]+|md\d+|sg\d+|st\d+|nst\d+)$/i;

/** Pipelines whose right side executes an interpreter are remote-fetch-exec
 *  regardless of the fetcher spelling. */
const PIPE_INTERPRETERS: Record<string, true> = {
  sh: true, bash: true, zsh: true, fish: true, python3: true, python: true,
  perl: true, ruby: true, node: true,
};

/** POSIX-family shells whose `-c` operand is literal shell text we can
 *  unwrap and re-analyze (B1: literal inline commands keep classifying). */
const POSIX_SHELLS: Record<string, true> = {
  sh: true, bash: true, zsh: true, dash: true, csh: true, tcsh: true, ksh: true, fish: true,
};

interface CommandInvocation {
  name: string;
  args: string[];
  /** Raw token text per arg: `'…'`-quoted operands are literal and must not
   *  get HOME/tilde expansion (R6). */
  rawArgs: string[];
}

interface PathArg {
  value: string;
  /** True when the token was fully single-quoted (literal `$HOME`, `~`). */
  literal: boolean;
}

function pathArg(rawToken: string | undefined): PathArg {
  const raw = rawToken ?? "";
  const singleQuoted = raw.length >= 2 && raw.startsWith("'") && raw.endsWith("'");
  const doubleQuoted = raw.length >= 2 && raw.startsWith("\"") && raw.endsWith("\"");
  const value = unquoteToken(raw);
  // Single quotes freeze everything; double quotes still allow $HOME but
  // never tilde expansion — `"~"` is a literal name (R6).
  const literal = singleQuoted || (doubleQuoted && /^~($|\/)/.test(value));
  return { value, literal };
}

/** Split at ;, &&, ||, newline, bare & and parens — but NOT single `|`
 *  (pipes stay inside a group so adjacent stages keep their fetcher→shell
 *  adjacency).  Quote- and escape-aware, same as splitShellCommands. */
function commandGroups(command: string): string[] {
  const result: string[] = [];
  let start = 0;
  let quote: string | undefined;
  let escaped = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) { escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === "\"" || ch === "`") { quote = ch; continue; }
    if (ch === ";" || ch === "\n" || ch === "(" || ch === ")") {
      const segment = command.slice(start, i).trim();
      if (segment) result.push(segment);
      start = i + 1;
      continue;
    }
    if (ch === "&") {
      const segment = command.slice(start, i).trim();
      if (segment) result.push(segment);
      if (command[i + 1] === "&") i++;
      start = i + 1;
      continue;
    }
    if (ch === "|" && command[i + 1] === "|") {
      const segment = command.slice(start, i).trim();
      if (segment) result.push(segment);
      start = i + 2;
      i++;
    }
  }
  const tail = command.slice(start).trim();
  if (tail) result.push(tail);
  return result;
}

/** Split one group at unquoted single `|` (skips `||`). */
function pipeStages(group: string): string[] {
  const result: string[] = [];
  let start = 0;
  let quote: string | undefined;
  let escaped = false;
  for (let i = 0; i < group.length; i++) {
    const ch = group[i];
    if (escaped) { escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === "\"" || ch === "`") { quote = ch; continue; }
    if (ch === "|" && group[i + 1] !== "|") {
      result.push(group.slice(start, i).trim());
      start = i + 1;
    }
  }
  result.push(group.slice(start).trim());
  return result.filter((stage) => stage.length > 0);
}

/**
 * The literal local command text launched inside a local wrapper —
 * `sudo rm -rf /` → `rm -rf /`, `ssh host chmod 777 /etc/x` → `chmod 777 /etc/x`,
 * `bash -c 'rm -rf /'` → `rm -rf /`.  Option parsing follows each tool's
 * operand grammar; unparseable wrappers return undefined (outer verdict
 * alone applies).  `~user`-style unknown expansions are never guessed.
 */
function innerWrappedCommand(invocation: CommandInvocation): string | undefined {
  const { name, args } = invocation;
  if (name === "sudo" || name === "doas") {
    const optionWithValue = new Set(["-u", "--user", "-g", "--group", "-C", "--close-from",
      "-D", "--chdir", "-h", "--host", "-p", "--prompt", "-R", "--role", "-t", "--type",
      "-T", "--command-timeout", "-U", "--other-user"]);
    let i = 0;
    while (i < args.length) {
      const arg = args[i];
      if (arg === "--") { i++; break; }
      if (!arg.startsWith("-")) break;
      if (optionWithValue.has(arg)) { i += 2; continue; }
      if (/^-[a-zA-Z]+$/.test(arg) || arg.startsWith("--")) { i++; continue; }
      i++;
    }
    return args.slice(i).map((arg) => /\s/.test(arg) ? quoteShellArgument(arg) : arg).join(" ") || undefined;
  }
  if (name === "ssh") {
    const optionWithValue = new Set(["-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i",
      "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"]);
    let i = 0;
    while (i < args.length) {
      const arg = args[i];
      if (arg === "--") { i++; break; }
      if (!arg.startsWith("-")) break;
      if (optionWithValue.has(arg)) { i += 2; continue; }
      i++;
    }
    // First operand is user@host.  The remote side joins its argv into a
    // shell command line, so re-quoting every operand would collapse the
    // whole remote command into one program name (R4); join plainly.
    return args.slice(i + 1).join(" ") || undefined;
  }
  if (POSIX_SHELLS[name] === true) {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      // `c` ends a short-option cluster: `-c` and combined `-xc`/`-lc`
      // both carry a literal script operand (R4).
      const scriptOption =
        arg === "-c" || (/^-[^-]*c$/.test(arg) && arg.length > 2);
      if (scriptOption && args[i + 1] !== undefined) return args[i + 1];
    }
  }
  return undefined;
}

/**
 * The program a pipeline stage actually executes, for remote-fetch-exec
 * adjacency (R1): env wrappers and sudo/doas unwrap to their inner program;
 * `xargs` keeps its own identity (piped data become arguments, not a script);
 * POSIX `-c` text is not unwrapped here — the stage head is the shell.
 */
function pipeStageProgram(segment: string): string | undefined {
  const invocation = commandAndArgs(segment, { unwrapXargs: false });
  if (!invocation) return undefined;
  if (invocation.name === "sudo" || invocation.name === "doas") {
    const inner = innerWrappedCommand(invocation);
    if (inner === undefined) return invocation.name;
    return commandAndArgs(inner, { unwrapXargs: false })?.name;
  }
  return invocation.name;
}

/** Expand the HOME forms resolvable without running the shell (~, $HOME,
 *  ${HOME}).  Any other $/`/glob/`~user` form is dynamic → undefined. */
function expandHomeLiteral(value: string, home: string): string | undefined {
  let expanded = value;
  if (!expanded) return undefined;
  if (expanded === "~") expanded = home;
  else if (expanded.startsWith("~/")) expanded = path.join(home, expanded.slice(2));
  else if (expanded.startsWith("~")) return undefined; // ~user needs a lookup
  const placeholder = "\0HOME\0";
  expanded = expanded
    .replace(/\$\{HOME\}/g, placeholder)
    .replace(/\$HOME(?![A-Za-z0-9_])/g, placeholder);
  if (/[$`{}\[\]*?]/.test(expanded)) return undefined;
  return expanded.split(placeholder).join(home) || undefined;
}

function isSystemTarget(value: string): boolean {
  return value === "/" || PERMISSION_SYSTEM_PATH_RE.test(value);
}

/** Recognized option clusters for the permission tools; anything else
 *  starting with `-` is an operand (e.g. the symbolic mode `-w`, R6). */
const PERMISSION_SHORT_OPTIONS_RE = /^-[RvcfHLPdhn]+$/;

/** chmod/chown/chgrp operands with tool grammar: option args and the
 *  leading MODE / OWNER[:GROUP] / GROUP operand are identified by role —
 *  `--reference` removes the role operand entirely; `chown --reference`
 *  carries the reference file as `reference` (its owner is dynamic; R6). */
function permissionTargets(
  invocation: CommandInvocation,
): { targets: PathArg[]; owner?: string; reference?: PathArg } {
  const { name, args, rawArgs } = invocation;
  let i = 0;
  let skipFirstOperand = true;
  let reference: PathArg | undefined;
  while (i < args.length) {
    const arg = args[i];
    if (arg === "--") { i++; break; }
    if (arg.startsWith("--")) {
      if (arg.startsWith("--reference=")) {
        reference = pathArg(rawArgs[i]?.slice("--reference=".length));
        skipFirstOperand = false;
        i++;
        continue;
      }
      if (arg === "--reference") {
        reference = pathArg(rawArgs[i + 1]);
        skipFirstOperand = false;
        i += 2;
        continue;
      }
      // Long options without a value (--recursive, --silent, …).
      i++;
      continue;
    }
    if (arg.startsWith("-") && PERMISSION_SHORT_OPTIONS_RE.test(arg)) { i++; continue; }
    break;
  }
  const operandArgs = args.slice(i).map((_, j) => pathArg(rawArgs[i + j]));
  const list = skipFirstOperand ? operandArgs.slice(1) : operandArgs;
  let owner: string | undefined;
  if (name === "chown" && skipFirstOperand) {
    const spec = operandArgs[0]?.value;
    const ownerPart = spec?.split(":")[0];
    owner = ownerPart === "" ? undefined : ownerPart;
  }
  return { targets: list, owner, reference };
}

/**
 * Classify one chmod/chown/chgrp invocation by target domain.  `cwd` is the
 * effective cwd at the segment executing it.  Targets are expanded for ~ and
 * $HOME (single-quoted literals stay literal — R6), resolved with realpath
 * semantics, and checked for system dirs, the root dir, and the home root.
 * `chown --reference FILE` takes FILE's owner: a stat-able file with a
 * different uid is system, an unresolvable reference leaves the owner
 * undetermined (the caller treats it like a reviewable unknown — R6).
 */
function permissionChangeTier(
  invocation: CommandInvocation,
  cwd: string,
  cwdKnown: boolean,
  home = process.env.HOME || os.homedir(),
  user = process.env.USER || os.userInfo().username,
): "permission-change-system" | "permission-change-user" {
  const { name } = invocation;
  const { targets, owner, reference } = permissionTargets(invocation);

  if (name === "chown" || name === "chgrp") {
    if (owner !== undefined && owner !== user) {
      return "permission-change-system";
    }
    if (reference !== undefined) {
      const refPath = expandPathTarget(reference, home);
      let refOther = false;
      if (refPath !== undefined) {
        const refCandidates = cwdKnown
          ? semanticPathCandidates(refPath, cwd, { expandHome: false })
          : [refPath];
        try {
          const stat = fs.statSync(refCandidates[refCandidates.length - 1] ?? refPath);
          refOther = name === "chgrp"
            ? !(process.getgroups?.() ?? [process.getgid?.() ?? -1]).includes(stat.gid)
            : stat.uid !== (process.getuid?.() ?? -1);
        } catch {
          refOther = false; // unresolvable reference → reviewable unknown
        }
        if (refOther) return "permission-change-system";
      }
    }
  }

  const homeCandidates = resolveFilesystemPathCandidates(home, home);
  for (const target of targets) {
    const expanded = expandPathTarget(target, home);

    if (expanded === undefined) continue; // dynamic — reviewable, LLM judges
    if (isSystemTarget(expanded)) return "permission-change-system";
    const candidates = cwdKnown
      ? semanticPathCandidates(expanded, cwd, { expandHome: false })
      : resolveFilesystemPathCandidates(expanded, home, { expandHome: false });
    for (const candidate of candidates) {
      if (isSystemTarget(candidate)) return "permission-change-system";
      if (homeCandidates.some((root) => candidate === root)) {
        return "permission-change-system";
      }
    }
  }
  return "permission-change-user";
}

/** Expand a PathArg: literal (single-quoted) values pass through untouched;
 *  unquoted values get the static HOME/tilde expansion (R6). */
function expandPathTarget(target: PathArg, home: string): string | undefined {
  if (target.literal) return target.value === "" ? undefined : target.value;
  return expandHomeLiteral(target.value, home);
}

/**
 * Filesystem targets of one stage for domain-scoped allow entries.
 * `complete:false` means the operand grammar wasn't fully understood —
 * the domain entry must not match (falls back to normal approval).
 */
/** Options whose VALUE is a filesystem path (output/config/input files). */
const FILE_OPTION_VALUE: Record<string, ReadonlySet<string>> = {
  tar: new Set(["-f", "--file", "-C", "--directory"]),
  curl: new Set(["-o", "--output", "-T", "--upload-file",
    "-K", "--config", "--cacert", "--cert", "--key", "-E",
    "-b", "--cookie", "-c", "--cookie-jar"]),
  wget: new Set(["-O", "--output-document", "-P", "--directory-prefix",
    "-i", "--input-file", "--ca-certificate", "--certificate", "--private-key",
    "--ca-directory", "--post-file", "--load-cookies", "--save-cookies"]),
  sort: new Set(["-o", "--output", "-T", "--temporary-directory",
    "--random-source", "--files0-from"]),
  git: new Set(["-C", "--git-dir", "--work-tree"]),
  ssh: new Set(["-i", "-F"]),
};

/** Options that take a non-file value — skipped wholesale. */
const NONFILE_OPTION_VALUE: Record<string, ReadonlySet<string>> = {
  curl: new Set(["-A", "--user-agent", "-H", "--header", "-d", "--data",
    "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form",
    "-u", "--user", "-x", "--proxy", "-X", "--request", "--connect-timeout",
    "-m", "--max-time", "--retry", "-e", "--referer",
    "--resolve", "--limit-rate", "--range",
    "--dns-servers", "--interface", "--local-port", "--ciphers"]),
  wget: new Set(["--header", "--post-data", "--user",
    "--password", "--timeout", "--tries", "--wait", "--limit-rate",
    "--bind-address", "--referer", "--user-agent",
    "-e", "--execute", "-U"]),
  find: new Set(["-path", "-name", "-iname", "-type", "-perm", "-user", "-group",
    "-size", "-newer", "-regex", "-maxdepth", "-mindepth", "-exec", "-execdir", "-ok", "-okdir"]),
  sort: new Set(["-k", "-t", "-S", "--buffer-size",
    "--compress-program", "--parallel"]),
  ssh: new Set(["-b", "-c", "-D", "-E", "-e", "-I", "-J", "-L", "-l", "-m",
    "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"]),
};

/** Remote operands (URL / scp-style host:path / rsync host::module) are not
 *  filesystem targets; anything else on a network tool is undeterminable. */
const REMOTE_OPERAND_RE =
  /^(?:[A-Za-z][A-Za-z0-9+.-]*:\/\/|[A-Za-z][A-Za-z0-9+.-]*:|\w[\w.-]*@[\w.-]+:|[^/]+::)/;

/** Commands whose operands are never filesystem paths for domain scoping. */
const NON_FILE_COMMANDS: ReadonlySet<string> = new Set([
  "echo", "printf", "true", "false", "test", "[", "sleep", "date", "uname",
  "hostname", "whoami", "id", "groups", "tty", "uptime", "which", "type",
  "command", "env", "export", "set", "unset", "alias", "history", "jobs",
  "fg", "bg", "wait", "kill", "pkill", "killall", "ps", "pwd", "exit",
  "return", "eval", "source", ".", "exec", "time", "times", "ulimit",
  "umask", "trap", "shift", "getopts", "read", "echo-e", "seq", "yes",
  "xargs", "nohup", "nice", "timeout", "watch", "clear", "reset",
  "gh", "npm", "npx", "pnpm", "yarn", "bun", "deno", "pip", "pip3",
  "python3", "python", "node", "ruby", "perl", "php", "lua", "docker",
  "kubectl", "systemctl", "service", "scp",
  "openssl", "nc", "netcat", "ncat", "socat", "telnet", "ping", "dig",
  "nslookup", "host", "traceroute", "grep", "rg", "egrep", "fgrep", "sed",
  "awk", "gawk", "diff", "wc", "uniq", "comm", "cut", "tr", "head",
  "tail", "less", "more", "man", "info", "apropos", "fd", "rg", "jq", "yq",
]);

interface FileTargetResult {
  targets: PathArg[];
  /** False → operand grammar unclear; domain entries must not apply. */
  complete: boolean;
}

/** Operand PathArgs of a stage, honoring `--` and known option values. */
function stagePathArgs(
  rawArgs: string[],
  optionWithValue?: ReadonlySet<string>,
): PathArg[] {
  const operands: PathArg[] = [];
  let i = 0;
  let optionsDone = false;
  while (i < rawArgs.length) {
    const raw = rawArgs[i];
    const arg = unquoteToken(raw);
    if (!optionsDone && arg === "--") { optionsDone = true; i++; continue; }
    if (!optionsDone && arg.startsWith("-")) {
      if (optionWithValue?.has(arg)) { i += 2; continue; }
      if (arg.includes("=")) { i++; continue; }
      i++;
      continue;
    }
    operands.push(pathArg(raw));
    i++;
  }
  return operands;
}

/** File-valued option arguments of a stage (output files, config files,
 *  upload sources — R2: download output options count as targets). */
function stageFileOptionTargets(
  name: string,
  rawArgs: string[],
): { targets: PathArg[]; complete: boolean } {
  const targets: PathArg[] = [];
  const fileOpts = FILE_OPTION_VALUE[name];
  const nonfileOpts = NONFILE_OPTION_VALUE[name];
  let complete = true;
  let i = 0;
  while (i < rawArgs.length) {
    const arg = unquoteToken(rawArgs[i]);
    if (arg === "--") break;
    if (!arg.startsWith("-")) { i++; continue; }
    if (arg.includes("=")) {
      const eq = arg.indexOf("=");
      if (fileOpts?.has(arg.slice(0, eq))) {
        targets.push({ value: arg.slice(eq + 1), literal: false });
      }
      i++;
      continue;
    }
    if (fileOpts?.has(arg)) {
      if (rawArgs[i + 1] === undefined) complete = false;
      else targets.push(pathArg(rawArgs[i + 1]));
      i += 2;
      continue;
    }
    if (nonfileOpts?.has(arg)) { i += 2; continue; }
    i++;
  }
  return { targets, complete };
}

function fileTargetsOfInvocation(
  invocation: CommandInvocation,
): FileTargetResult {
  const { name, args, rawArgs } = invocation;
  if (name === "dd") {
    const values = args
      .filter((arg) => /^(?:of|if)=/.test(arg))
      .map((arg) => ({ value: arg.slice(arg.indexOf("=") + 1), literal: false }));
    return { targets: values, complete: true };
  }
  if (["chmod", "chown", "chgrp"].includes(name)) {
    const result = permissionTargets(invocation);
    const targets = [...result.targets];
    if (result.reference) targets.push(result.reference);
    return { targets, complete: true };
  }
  if (name === "scp") {
    const operands = stagePathArgs(rawArgs);
    return {
      targets: operands.filter((arg) => !/^[^/]*:/.test(arg.value)),
      complete: true,
    };
  }
  if (name === "ssh") {
    // Only file-valued options are local paths; the remote command is remote.
    const { targets, complete } = stageFileOptionTargets(name, rawArgs);
    return { targets, complete };
  }
  if (name === "curl" || name === "wget") {
    // Network fetchers: file targets are the OPTION values (-o/-O/-i/…);
    // bare operands are URLs, not paths.  `@file` operands of -d/-F/--form
    // read a local file too (R2).
    const { targets, complete } = stageFileOptionTargets(name, rawArgs);
    for (let i = 0; i < rawArgs.length; i++) {
      const arg = unquoteToken(rawArgs[i]);
      if (["-d", "--data", "--data-raw", "--data-binary", "-F", "--form"].includes(arg)) {
        const value = unquoteToken(rawArgs[i + 1] ?? "");
        if (value.startsWith("@")) targets.push(pathArg(rawArgs[i + 1]));
        i++;
      }
    }
    const remoteOnly = stagePathArgs(rawArgs).every(
      (operand) => REMOTE_OPERAND_RE.test(operand.value) ||
        /^[A-Za-z][A-Za-z0-9+.-]*(?::\d+)?\//.test(operand.value) ||
        operand.value.includes("."),
    );
    return { targets, complete: complete && remoteOnly };
  }
  if (name === "tee") {
    const operands = stagePathArgs(rawArgs);
    return { targets: operands, complete: true };
  }
  if (name === "tar") {
    const { targets, complete } = stageFileOptionTargets(name, rawArgs);
    const operands = stagePathArgs(rawArgs, FILE_OPTION_VALUE.tar);
    // A leading non-dash operand is the action bundle (`xf`, `czf`); with
    // `-x` style flags every operand is a path (archive or member).
    const leadingAction = args[0] !== undefined && !args[0].startsWith("-");
    return {
      targets: [...targets, ...(leadingAction ? operands.slice(1) : operands)],
      complete,
    };
  }
  if (name === "sort") {
    // Option VALUES and bare operands are all files (input files).
    const { targets, complete } = stageFileOptionTargets(name, rawArgs);
    const skip = new Set<string>([
      ...(FILE_OPTION_VALUE.sort ?? []),
      ...(NONFILE_OPTION_VALUE.sort ?? []),
    ]);
    const operands = stagePathArgs(rawArgs, skip);
    return { targets: [...targets, ...operands], complete };
  }
  if (name === "git") {
    // Only file-valued options are paths (-C/--git-dir/--work-tree); the
    // subcommand and its operands are repo objects, not local files.
    const { targets, complete } = stageFileOptionTargets(name, rawArgs);
    return { targets, complete };
  }
  if (NON_FILE_COMMANDS.has(name)) return { targets: [], complete: true };

  // Filesystem utilities: every operand is a path.
  const FILE_COMMANDS = new Set([
    "cat", "ls", "dir", "stat", "file", "touch", "mkdir", "rmdir", "rm",
    "cp", "mv", "install", "ln", "link", "unlink", "readlink", "realpath",
    "basename", "dirname", "du", "df", "tree", "find", "locate", "which",
    "mktemp", "gzip", "gunzip", "zip", "unzip", "xz", "bzip2", "zstd",
    "md5sum", "sha1sum", "sha256sum", "cksum", "patch", "diff3", "vim",
    "vi", "nano", "emacs", "code", "open", "xdg-open", "gpg", "git-add",
  ]);
  if (FILE_COMMANDS.has(name)) {
    const skip = new Set<string>([...(FILE_OPTION_VALUE[name] ?? [])]);
    for (const option of NONFILE_OPTION_VALUE[name] ?? []) skip.add(option);
    const { targets: optionTargets, complete } = stageFileOptionTargets(name, rawArgs);
    const operands = stagePathArgs(rawArgs, skip);
    return { targets: [...optionTargets, ...operands], complete };
  }
  // Unknown command with operands: cannot prove domain membership.
  const operands = stagePathArgs(rawArgs);
  return { targets: [], complete: operands.length === 0 };
}

/**
 * Extract every filesystem target of a normalized command for `domain`
 * allow entries.  Honors quotes (roughTokenize preserves quoted spacing)
 * and per-segment `cd` state.  `undeterminable` is set when any stage's
 * operand grammar or dynamic expansion can't be resolved — the caller must
 * treat the domain check as failed (normal approval), not allowed.
 */
export function commandFileTargets(
  command: string,
  cwd: string,
): { targets: { value: string; cwd: string }[]; undeterminable: boolean } {
  const targets: { value: string; cwd: string }[] = [];
  let undeterminable = false;
  let currentCwd = cwd;
  let cwdKnown = true;

  const pending: { text: string; cwd: string; cwdKnown: boolean }[] = [
    { text: normalize(command), cwd, cwdKnown: true },
  ];
  while (pending.length > 0) {
    const entry = pending.pop()!;
    currentCwd = entry.cwd;
    cwdKnown = entry.cwdKnown;
    const substitutions = findShellSubstitutions(entry.text);
    for (const substitution of substitutions) {
      undeterminable = true; // executed payload we can't statically scope
      pending.push({ text: substitution.body, cwd: currentCwd, cwdKnown });
    }
    const executableCommand = stripShellSubstitutions(entry.text, substitutions);
    for (const group of commandGroups(executableCommand)) {
      const stages = pipeStages(group);
      for (const stage of stages) {
        const invocation = commandAndArgs(stage);
        if (!invocation) continue;
        const { name, args } = invocation;

        const inner = innerWrappedCommand(invocation);
        if (inner !== undefined) {
          pending.push({ text: inner, cwd: currentCwd, cwdKnown });
        } else if (name === "sudo" || name === "doas" || name === "ssh") {
          undeterminable = true; // wrapper whose inner command can't be proven
        }
        if (name === "find") {
          for (const commandArgs of findExecCommands(args)) {
            pending.push({
              text: commandArgs.map(quoteShellArgument).join(" "),
              cwd: currentCwd,
              cwdKnown,
            });
          }
        }

        if (name === "cd") {
          const index = args.findIndex((arg) => arg !== "--" && !arg.startsWith("-"));
          const home = process.env.HOME || os.homedir();
          const operand = index >= 0 ? pathArg(invocation.rawArgs[index]) : undefined;
          const expanded = operand === undefined
            ? home
            : expandPathTarget(operand, home);
          if (expanded === undefined || !cwdKnown) {
            cwdKnown = false;
            continue;
          }
          const candidates = semanticPathCandidates(expanded, currentCwd, { expandHome: false });
          currentCwd = candidates[candidates.length - 1] ?? expanded;
          continue;
        }

        const result = fileTargetsOfInvocation(invocation);
        if (!result.complete) undeterminable = true;
        const home = process.env.HOME || os.homedir();
        for (const target of result.targets) {
          const expanded = expandPathTarget(target, home);
          if (expanded === undefined) {
            undeterminable = true;
            continue;
          }
          targets.push({ value: expanded, cwd: currentCwd });
        }

        // Redirection targets are filesystem targets too (R2); /dev/null
        // is the universal sink and carries no domain risk.
        for (const raw of redirectionTargets(stage)) {
          const expanded = expandPathTarget(pathArg(raw), home);
          if (expanded === undefined) {
            undeterminable = true;
            continue;
          }
          if (expanded === "/dev/null") continue;
          targets.push({ value: expanded, cwd: currentCwd });
        }
      }
    }
  }
  return { targets, undeterminable };
}


/**
 * True when `cwd` is inside a sensitive system location and outside the
 * session root.  Lexical and canonical candidates are compared for both the
 * working directory and every sensitive directory, so a symlinked
 * `~/.ssh` / `~/.gnupg` is still recognized after canonicalization.
 * Relative `cwd` values resolve against `baseCwd` (defaulting to
 * `sessionCwd`); URLs are not local.  Shared with the Eval gate for its cwd
 * checks.
 */
export function isSensitiveWorkingDirectory(
  cwd: string,
  sessionCwd: string,
  baseCwd = sessionCwd,
): boolean {
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(cwd)) return false;
  const candidates = resolveFilesystemPathCandidates(cwd, baseCwd);
  if (candidates.length === 0) return false;

  const home = process.env.HOME || os.homedir();
  const sensitiveSystemCandidates = SENSITIVE_DIRS.flatMap((directory) =>
    resolveFilesystemPathCandidates(directory, directory),
  );
  const sensitiveHomeCandidates = [path.join(home, ".ssh"), path.join(home, ".gnupg")]
    .flatMap((directory) => resolveFilesystemPathCandidates(directory, directory));
  const temporaryCandidates = TEMPORARY_DIRS.flatMap((directory) =>
    resolveFilesystemPathCandidates(directory, directory),
  );

  const sensitive = candidates.some((candidate) =>
    sensitiveHomeCandidates.some((directory) => isWithinDirectory(candidate, directory)) ||
    (
      sensitiveSystemCandidates.some((directory) => isWithinDirectory(candidate, directory)) &&
      !temporaryCandidates.some((directory) => isWithinDirectory(candidate, directory))
    ),
  );
  if (!sensitive) return false;

  const sessionCandidates = resolveFilesystemPathCandidates(sessionCwd, sessionCwd);
  return !candidates.some((candidate) =>
    sessionCandidates.some(
      (directory) =>
        candidate === directory ||
        candidate.startsWith(directory === path.sep ? path.sep : `${directory}${path.sep}`),
    ),
  );
}


// ── Git argument parser ──────────────────────────────────────────────
//
// Parses git subcommand + flags to detect behaviors that regex misses
// (e.g. `git push origin +branch` = force-push via +refspec).

function roughTokenize(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: string | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
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


function skipGitGlobalOptions(args: string[]): { subcommand: string; rest: string[] } | null {
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) {
    if (["-C", "--git-dir", "--work-tree", "-c"].includes(args[i])) i += 2;
    else i += 1;
    if (i > args.length) return null;
  }
  if (i >= args.length) return null;
  return { subcommand: args[i], rest: args.slice(i + 1) };
}

function isForcePush(args: string[]): boolean {
  for (const arg of args) {
    if (arg === "-f" || arg === "--force" || arg === "--mirror") return true;
    if (arg === "--force-with-lease" || arg.startsWith("--force-with-lease=")) return true;
    if (arg === "--force-if-includes") return true;
    if (arg.startsWith("+") && arg.length > 1 && !arg.startsWith("+-")) return true;
  }
  return false;
}

/** Branches whose force push is deny-tier (regex-confident without AI). */
const PROTECTED_PUSH_BRANCHES: Record<string, true> = {
  main: true, master: true, production: true, prod: true, release: true, trunk: true,
};

/** Extract candidate remote branch names from push args (refspecs). */
function pushTargetBranches(args: string[]): string[] {
  const branches: string[] = [];
  for (const arg of args) {
    if (arg === "--") break;
    if (arg.startsWith("-")) continue;
    let target = arg;
    if (target.includes(":")) target = target.slice(target.lastIndexOf(":") + 1);
    if (target.startsWith("+")) target = target.slice(1);
    // Keep only the leaf: refs/heads/main -> main, origin/main -> main.
    target = target.slice(target.lastIndexOf("/") + 1);
    if (target) branches.push(target);
  }
  return branches;
}

/**
 * Match a long option by any nonempty leading prefix without "=".
 *
 * Git accepts unique option abbreviations ("--delet" for "--delete"), so
 * equality checks would let "--delet --forc" slip past the plain-delete
 * review. Prefixes shared by several options are accepted too: git rejects
 * the ambiguous command itself, so a conservative match cannot misclassify
 * a command that actually runs.
 */
function isLongOptionPrefix(arg: string, option: string): boolean {
  if (!arg.startsWith("--") || arg.includes("=")) return false;
  const prefix = arg.slice(2);
  return prefix.length > 0 && option.startsWith(prefix);
}

/**
 * Classify `git branch` deletion flags.
 *
 * Every local branch delete needs review, including plain "-d"/"--delete".
 * Git does not require `-d` to be merged into HEAD: it checks the branch's
 * configured upstream (`branch.<name>.remote`/`.merge`), which command-local
 * `-c` config can point anywhere. A merged-looking delete can therefore
 * discard commits that HEAD cannot reach. "-D" and "-f"/"--force" force the
 * delete; both long forms may be abbreviated like git itself does.
 * "-r"/"--remotes" selects remote-tracking refs, which get their own
 * accurate label. Options after "--" are branch names, not flags.
 */
function analyzeBranchDelete(args: string[]): string[] {
  let deleting = false;
  let remotes = false;
  for (const arg of args) {
    if (arg === "--") break;
    if (isLongOptionPrefix(arg, "delete")) deleting = true;
    else if (isLongOptionPrefix(arg, "remotes")) remotes = true;
    else if (/^-[^-]/.test(arg)) {
      for (const flag of arg.slice(1)) {
        if (flag === "d" || flag === "D") deleting = true;
        else if (flag === "r") remotes = true;
        // "-u" takes the rest of the cluster as its argument.
        else if (flag === "u") break;
      }
    }
  }
  if (!deleting) return [];
  if (remotes) return ["git-branch-delete-remote"];
  return ["git-branch-delete"];
}

function isGitCleanDestructive(args: string[]): boolean {
  for (const arg of args) {
    if (arg === "-n" || arg === "--dry-run") return false;
  }
  for (const arg of args) {
    if (arg === "--") break;
    if (["-f", "--force", "-x", "-X", "-d", "--directories"].includes(arg)) return true;
    if (arg.startsWith("-") && !arg.startsWith("--")) {
      if (/[fxXd]/.test(arg)) return true;
    }
  }
  return false;
}

function isGlobalPackageUninstall(name: string, args: string[]): boolean {
  const globalFlag = args.some((arg) => arg === "-g" || arg === "--global" || arg.startsWith("--global="));
  if (["npm", "pnpm"].includes(name)) {
    return ["uninstall", "remove", "rm"].includes(args[0] ?? "") && globalFlag;
  }
  if (name === "yarn") {
    return (
      (args[0] === "global" && ["remove", "uninstall"].includes(args[1] ?? "")) ||
      (["remove", "uninstall"].includes(args[0] ?? "") && globalFlag)
    );
  }
  return /^pip(?:\d+(?:\.\d+)*)?$/.test(name) && args[0] === "uninstall";
}


/** Detect git behaviors by parsing arguments. Returns behavior ids. */
function analyzeGit(args: string[]): string[] {
  const skipped = skipGitGlobalOptions(args);
  if (!skipped) return [];
  const { subcommand, rest } = skipped;
  switch (subcommand) {
    case "push": {
      const ids: string[] = [];
      if (isForcePush(rest)) {
        ids.push("git-force-push");
        if (pushTargetBranches(rest).some((branch) => PROTECTED_PUSH_BRANCHES[branch] === true)) {
          ids.push("git-force-push-protected");
        }
      }
      if (rest.includes("--delete") || rest.some((arg) => arg.startsWith("--delete="))) {
        ids.push("git-push-delete");
      }
      if (rest.some((arg) => arg.startsWith(":") && arg.length > 1)) {
        ids.push("git-push-colon-ref");
      }
      return ids;
    }
    case "branch":
      return analyzeBranchDelete(rest);
    case "worktree":
      return (rest[0] === "remove" || rest[0] === "rm") ? ["git-worktree-remove"] : [];
    case "reset":
      return rest.includes("--hard") ? ["git-hard-reset"] : [];
    case "clean":
      return isGitCleanDestructive(rest) ? ["git-clean"] : [];
    case "tag":
      return rest.some((arg) => arg === "-d" || arg === "--delete" || /^-[^-]*d/.test(arg))
        ? ["git-tag-delete"]
        : [];
    case "stash":
      return rest[0] === "clear"
        ? ["git-stash-clear"]
        : rest[0] === "drop"
          ? ["git-stash-drop"]
          : [];
    case "reflog":
      return rest[0] === "expire" ? ["git-reflog-expire"] : [];
    case "gc":
      return rest.some((arg) => arg === "--prune" || arg.startsWith("--prune="))
        ? ["git-gc-prune"]
        : [];
    case "filter-branch":
      return ["git-filter-branch"];
    case "filter-repo":
      return ["git-filter-repo"];
    case "commit":
      return rest.includes("--amend") ? ["git-commit-amend"] : [];
    case "remote":
      return ["rm", "remove"].includes(rest[0] ?? "") ? ["git-remote-rm"] : [];
    case "submodule":
      return rest[0] === "deinit" ? ["git-submodule-deinit"] : [];
    case "update-ref":
      return rest.some((arg) => arg === "-d" || arg === "--delete" || /^-[^-]*d/.test(arg))
        ? ["git-update-ref-delete"]
        : [];
    case "checkout": {
      const separator = rest.indexOf("--");
      return separator >= 0 && rest.length > separator + 1 ? ["git-checkout-discard"] : [];
    }
    case "restore":
      return rest.some((arg) => !arg.startsWith("-") && arg !== "--")
        ? ["git-restore-discard"]
        : [];
    case "config":
      return rest.some((arg) => arg === "--global" || arg.startsWith("--global="))
        ? ["git-config-global"]
        : [];
    case "rebase":
      return ["--abort", "--continue", "--skip"].includes(rest[0] ?? "") ? [] : ["git-rebase"];
    case "notes": {
      let index = 0;
      while (index < rest.length && rest[index].startsWith("-")) {
        if (rest[index] === "--ref") index += 2;
        else index++;
      }
      return rest[index] === "remove" ? ["git-notes-remove"] : [];
    }
    default:
      return [];
  }
}

// ── Composite analysis ───────────────────────────────────────────────

/** Behaviors that are always hard-blocked (no LLM review, no allow).
 *  Irreversible-by-construction operations only (DESIGN §三): recursive
 *  deletes of root/home/system paths, fork bombs, fetch-and-execute pipes,
 *  system account-file access, raw device writes, filesystem formatting,
 *  reverse-shell pivots, system/home-root permission changes, and dd to
 *  block devices.  Wrapped and eval-spawned forms merge the same verdict. */
const HARD_BLOCK_BEHAVIORS: Record<string, true> = {
  "recursive-force-delete": true,
  "delete-root": true,
  "fork-bomb": true,
  "remote-fetch-exec": true,
  "write-sensitive-file": true,
  "sensitive-file-reference": true,
  "write-block-device": true,
  "disk-format": true,
  "high-risk-shell-pivot": true,
  "chmod-sys-dir": true,
  "permission-change-system": true,
  "dd-block-device": true,
};

/** Deny-tier behaviors: regex-confident enough to block without an LLM
 *  verdict when auto mode falls back to regex-only decisions.  Hard-blocked
 *  commands never report deny tier — the harder tier wins. */
const DENY_TIER_BEHAVIORS: Record<string, true> = {
  "git-force-push-protected": true,
  "permission-change-system": true,
  "dd-block-device": true,
};

/** Normalize shell input without treating `#` inside quotes as a comment. */
export function normalize(cmd: string): string {
  return stripShellComments(String(cmd ?? ""))
    .replace(/[ \t\r]+/g, " ")
    .replace(/\n{2,}/g, "\n")
    .trim();
}

/**
 * Match parsed executable positions and arguments. Narrow syntax patterns
 * handle shell constructs; command substitutions are analyzed separately,
 * while commit messages, output data, and comments remain data.
 */
export function analyzeCommand(cmd: string): DangerAnalysis {
  const behaviorSet = new Set<string>();
  const pending = [String(cmd ?? "")];

  while (pending.length > 0) {
    const command = normalize(pending.pop() ?? "");
    const substitutions = findShellSubstitutions(command);
    for (const substitution of substitutions) pending.push(substitution.body);

    const executableCommand = stripShellSubstitutions(command, substitutions);
    const syntax = stripQuotedShellData(executableCommand);

    for (const group of commandGroups(executableCommand)) {
      const stages = pipeStages(group);

      // remote-fetch-exec is judged on truly ADJACENT pairs (R1): a
      // fetch/source stage immediately feeding an interpreter stage.
      // Both ends use the executed program's basename — env wrappers and
      // sudo/doas unwrap, xargs does not — so `/usr/bin/curl x | /bin/sh`,
      // `sudo curl x | sh`, and `curl x | sudo sh` all match, while
      // `curl x; sh -c y` (independent commands) and quoted text do not.
      for (let index = 0; index + 1 < stages.length; index++) {
        const source = pipeStageProgram(stages[index]);
        const sink = pipeStageProgram(stages[index + 1]);
        if (
          source !== undefined &&
          sink !== undefined &&
          ["curl", "wget", "fetch", "echo", "printf"].includes(source) &&
          PIPE_INTERPRETERS[sink] === true
        ) {
          behaviorSet.add("remote-fetch-exec");
          break;
        }
      }

      for (const segment of stages) {
      const invocation = commandAndArgs(segment);
      if (!invocation) continue;
      const { name, args } = invocation;

      const inner = innerWrappedCommand(invocation);
      if (inner !== undefined) pending.push(inner);

      if (name === "git") {
        for (const behavior of analyzeGit(args)) behaviorSet.add(behavior);
      }
      if (name === "find") {
        for (const commandArgs of findExecCommands(args)) {
          pending.push(commandArgs.map(quoteShellArgument).join(" "));
        }
      }
      if (isGlobalPackageUninstall(name, args)) behaviorSet.add("pkg-global-uninstall");
      if (HIGH_RISK_NET_TOOLS[name] === true) behaviorSet.add("high-risk-net-tool");
      if (HIGH_RISK_SHELL_PIVOTS[name] === true) behaviorSet.add("high-risk-shell-pivot");
      if (PRIVILEGED_EXECS[name] === true) behaviorSet.add("privileged-exec");
      if (
        INTERPRETERS[name] === true ||
        /^(?:python(?:\d+(?:\.\d+)*)?|pypy\d*)$/.test(name) ||
        /^node\d+(?:\.\d+)*$/.test(name)
      ) {
        if (hasInterpreterExecutionFlag(args)) behaviorSet.add("interpreter-inline-execution");
      }
      // chmod/chown/chgrp are classified by target domain in
      // analyzeBashOperation (permission-change-system vs -user).

      const positional = args.filter((arg) => arg !== "--" && !arg.startsWith("-"));
      const destination = positional[positional.length - 1];
      const recursiveForce = name === "rm" && hasRecursiveForceFlags(args);
      if (recursiveForce) behaviorSet.add("recursive-force-delete");
      if (name === "rm" && positional.includes("/")) behaviorSet.add("delete-root");
      if (
        name === "rm" &&
        positional.some((target) =>
          /^\/(?:usr|etc|var|bin|sbin|boot|dev|proc|sys|root|home|Library)(?:\/|$)/i.test(target),
        )
      ) {
        behaviorSet.add("delete-sys-dir");
      }
      if (
        recursiveForce &&
        positional.some((target) =>
          target === "~" ||
          target.startsWith("~/") ||
          target === "$HOME" ||
          target.startsWith("$HOME/") ||
          /^\/Users\/[^/]+(?:\/|$)/.test(target),
        )
      ) {
        behaviorSet.add("delete-home");
      }
      // rmdir refuses non-empty directories; keep the baseline root-path
      // hard block instead of flagging every absolute target.
      if (name === "rmdir" && positional.includes("/")) {
        behaviorSet.add("recursive-force-delete");
      }

      if (
        ["shutdown", "poweroff", "halt", "reboot"].includes(name) ||
        (name === "init" && args.some((arg) => arg === "0" || arg === "6"))
      ) {
        behaviorSet.add("shutdown-reboot");
      }
      if (
        name === "systemctl" &&
        ["shutdown", "poweroff", "halt", "reboot"].includes(args.find((arg) => !arg.startsWith("-")) ?? "")
      ) {
        behaviorSet.add("shutdown-reboot");
      }

      if (hasSensitiveAccountFileReference(name, args)) {
        behaviorSet.add("sensitive-file-reference");
      }
      const writesSensitiveFile =
        (name === "tee" && positional.some((arg) => /^\/etc\/(?:passwd|shadow|sudoers|hosts)$/i.test(arg))) ||
        (["cp", "mv", "install", "sed", "perl"].includes(name) &&
          destination !== undefined &&
          /^\/etc\/(?:passwd|shadow|sudoers|hosts)$/i.test(destination));
      if (writesSensitiveFile) behaviorSet.add("write-sensitive-file");
      if (name === "dd" && args.some((arg) => /^of=/.test(arg))) {
        const ofTarget = args.find((arg) => /^of=/.test(arg))?.slice(3) ?? "";
        behaviorSet.add(
          BLOCK_DEVICE_PATH_RE.test(ofTarget.replace(/\\/g, "/"))
            ? "dd-block-device"
            : "dd-write",
        );
      }
      if (name === "mkfs" || name.startsWith("mkfs.")) behaviorSet.add("disk-format");
      if (
        (name === "mount" || name === "umount") &&
        args.some((arg) => /^\/dev\/(?:sd|nvme|disk)/i.test(arg))
      ) {
        behaviorSet.add("mount-block-device");
      }
      if (
        (name === "kill" && args.some((arg) => /^-(?:9|\d+)$/.test(arg))) ||
        (["pkill", "killall"].includes(name) && args.some((arg) => /-[a-zA-Z]*9/.test(arg)))
      ) {
        behaviorSet.add("force-kill");
      }
      if (name === "mv" && positional.some((target) =>
        /^\/(?:usr|etc|var|bin)(?:\/|$)/i.test(target),
      )) {
        behaviorSet.add("mv-sys-dir");
      }
      if (name === "cp" && args.some((arg) => /-[a-zA-Z]*r/i.test(arg)) && positional.includes("/")) {
        behaviorSet.add("cp-root");
      }
      if (
        name === "docker" &&
        (["rm", "rmi"].includes(args[0] ?? "") ||
          (["volume", "network"].includes(args[0] ?? "") && args[1] === "rm"))
      ) {
        behaviorSet.add("docker-destroy");
      }
      if (name === "kubectl" && args[0] === "delete") {
        behaviorSet.add("kubectl-delete");
      }

      for (const rawTarget of redirectionTargets(segment)) {
        const target = unquoteToken(rawTarget);
        const normalized = target.replace(/\\/g, "/");
        const sensitiveSystemWrite =
          /^(?:\/private)?\/etc\/(?:passwd|shadow|sudoers|hosts)(?:$|[./])/i.test(normalized) ||
          /^\/(?:proc|sys)(?:\/|$)/i.test(normalized);
        const blockDeviceWrite = BLOCK_DEVICE_PATH_RE.test(normalized);
        if (sensitiveSystemWrite || blockDeviceWrite) behaviorSet.add("write-sensitive-file");
        if (blockDeviceWrite) behaviorSet.add("write-block-device");
      }
      }
    }

    if (FORK_BOMB_PATTERN.test(syntax)) behaviorSet.add("fork-bomb");
  }

  const behaviors = [...behaviorSet];
  const labels = behaviors.map((behavior) => BEHAVIORS[behavior] || makeLabel(behavior, behavior));
  const hardBlocked = behaviors.some((behavior) => behavior in HARD_BLOCK_BEHAVIORS);
  const denyTier =
    !hardBlocked && behaviors.some((behavior) => behavior in DENY_TIER_BEHAVIORS);

  return { behaviors, labels, hardBlocked, denyTier };
}

/** Localized label lookup shared with the eval analyzer (B2). */
export function labelForBehavior(id: string): { en: string; zh: string } {
  return BEHAVIORS[id] || makeLabel(id, id);
}

/**
 * Analyze a command plus its explicit execution cwd.
 * Adds cwd/session-scoped behaviors on top of analyzeCommand:
 *  - permission-change → permission-change-system (hard) or -user (reviewable),
 *    classified per segment with `cd` tracking and realpath semantics (B5)
 *  - dd of= targets resolve against the effective cwd; existing block devices
 *    are detected by file type, not just spelling (B7)
 *  - sensitive-working-directory → reviewable (was hard block; DESIGN §3.1)
 *  - hasUI=false → shutdown-reboot requires confirmation (headless auto-reject, §九-1b)
 */
export function analyzeBashOperation(
  command: string,
  cwd: string,
  sessionCwd: string,
  options: {
    hasUI?: boolean;
    isBlockDevice?: (target: string) => boolean;
  } = {},
): DangerAnalysis {
  const hasUI = options.hasUI ?? true;
  const isBlockDevice = options.isBlockDevice ?? ((target: string): boolean => {
    try {
      return fs.statSync(target).isBlockDevice();
    } catch {
      return false;
    }
  });

  const analysis = analyzeCommand(command);

  const behaviorSet = new Set(analysis.behaviors);
  let currentCwd = cwd;
  let cwdKnown = true;
  const pending: { text: string; cwd: string; cwdKnown: boolean }[] = [
    { text: normalize(command), cwd, cwdKnown: true },
  ];
  while (pending.length > 0) {
    const entry = pending.pop()!;
    currentCwd = entry.cwd;
    cwdKnown = entry.cwdKnown;
    const substitutions = findShellSubstitutions(entry.text);
    for (const substitution of substitutions) {
      pending.push({ text: substitution.body, cwd: currentCwd, cwdKnown });
    }
    const executableCommand = stripShellSubstitutions(entry.text, substitutions);
    for (const group of commandGroups(executableCommand)) {
      for (const stage of pipeStages(group)) {
        const invocation = commandAndArgs(stage);
        if (!invocation) continue;
        const { name, args } = invocation;

        const inner = innerWrappedCommand(invocation);
        if (inner !== undefined) {
          pending.push({ text: inner, cwd: currentCwd, cwdKnown });
        }
        if (name === "find") {
          for (const commandArgs of findExecCommands(args)) {
            pending.push({
              text: commandArgs.map(quoteShellArgument).join(" "),
              cwd: currentCwd,
              cwdKnown,
            });
          }
        }

        if (name === "cd") {
          const index = args.findIndex((arg) => arg !== "--" && !arg.startsWith("-"));
          const home = process.env.HOME || os.homedir();
          const operand = index >= 0 ? pathArg(invocation.rawArgs[index]) : undefined;
          const expanded = operand === undefined ? home : expandPathTarget(operand, home);
          if (expanded === undefined || !cwdKnown) {
            cwdKnown = false;
            continue;
          }
          const candidates = semanticPathCandidates(expanded, currentCwd, { expandHome: false });
          currentCwd = candidates[candidates.length - 1] ?? expanded;
          continue;
        }

        if (["chmod", "chown", "chgrp"].includes(name)) {
          behaviorSet.add(permissionChangeTier(invocation, currentCwd, cwdKnown));
        }

        if (name === "dd") {
          for (let ai = 0; ai < args.length; ai++) {
            if (!/^of=/.test(args[ai])) continue;
            const ddTarget = pathArg(invocation.rawArgs[ai].slice(invocation.rawArgs[ai].indexOf("=") + 1));
            const expanded = expandPathTarget(
              ddTarget,
              process.env.HOME || os.homedir(),
            );
            if (expanded === undefined) {
              behaviorSet.add("dd-write");
              continue;
            }
            const candidates = cwdKnown
              ? semanticPathCandidates(expanded, currentCwd, { expandHome: false })
              : [expanded];
            const blockDevice = candidates.some(
              (candidate) =>
                BLOCK_DEVICE_PATH_RE.test(candidate.replace(/\\/g, "/")) ||
                isBlockDevice(candidate),
            );
            if (blockDevice) {
              behaviorSet.delete("dd-write");
              behaviorSet.add("dd-block-device");
            } else {
              behaviorSet.add("dd-write");
            }
          }
        }
      }
    }
  }

  if (isSensitiveWorkingDirectory(cwd, sessionCwd)) {
    behaviorSet.add("sensitive-working-directory");
  }

  const behaviors = [...behaviorSet];
  const labels = behaviors.map(labelForBehavior);
  const hardBlocked = behaviors.some((behavior) => behavior in HARD_BLOCK_BEHAVIORS);
  const denyTier =
    !hardBlocked && behaviors.some((behavior) => behavior in DENY_TIER_BEHAVIORS);
  const requiresConfirmation =
    (analysis.requiresConfirmation ?? false) ||
    (!hasUI && behaviorSet.has("shutdown-reboot"));

  return { behaviors, labels, hardBlocked, denyTier, requiresConfirmation };
}
