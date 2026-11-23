/**
 * Smart Approve — decision memory (allow-list).
 *
 * Tracks session (in-memory) and permanent (disk-persisted) allow
 * decisions so a repeated dangerous command doesn't re-prompt within
 * the same session or ever (if permanent).  Encapsulates key generation,
 * dedup, and persistence so the hook stays linear.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AllowEntry } from "./types";
import { normalize, commandFileTargets } from "./behaviors";
import { matchCommandGlob, resolveFilesystemPathCandidates, semanticPathCandidates } from "./paths";
import type { Logger } from "./logger";

/** Normalize a key for dedup: tool + normalized-content + cwd. */
function makeAllowKey(tool: string, content: string, cwd: string): string {
  const normalized = tool === "bash"
    ? normalize(content)
    : path.resolve(cwd, content);
  return `${tool}::${normalized}::${cwd}`;
}

/**
 * Allow-list with session + permanent tiers.
 * Session allows live in-memory; permanent allows are JSON-persisted.
 */
export class AllowList {
  private readonly sessionAllows = new Set<string>();
  private permanent: AllowEntry[];
  private readonly allowListPath: string;

  constructor(allowListPath: string, private readonly logger?: Logger) {
    this.allowListPath = allowListPath;
    this.permanent = this.loadPermanent();
  }

  /** Load permanent allow-list from disk. */
  private loadPermanent(): AllowEntry[] {
    try {
      if (fs.existsSync(this.allowListPath)) {
        const raw = fs.readFileSync(this.allowListPath, "utf-8");
        const data = JSON.parse(raw);
        if (Array.isArray(data.permanent)) return data.permanent;
        if (Array.isArray(data)) return data; // legacy format
      }
    } catch {
      // ignore
    }
    return [];
  }

  /** Save permanent allow-list to disk. */
  private savePermanent(): void {
    try {
      const dir = path.dirname(this.allowListPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.allowListPath, JSON.stringify({ permanent: this.permanent }, null, 2), "utf-8");
    } catch {
      // best-effort; don't block execution
    }
  }

  /**
   * Check if a decision is remembered (session or permanent).
   * Legacy exact entries stay cwd-scoped.  Entries carrying `pattern`
   * and/or `domain` must satisfy ALL of their constraints (B3): the glob
   * matches the full normalized command at argument boundaries, and every
   * filesystem target resolves inside the domain — including quoted,
   * relative, and symlinked targets (B4).  Undeterminable targets make the
   * domain check fail so the command falls back to normal approval.
   */
  isAllowed(tool: string, content: string, cwd: string, analysisCwd = cwd): boolean {
    const key = makeAllowKey(tool, content, cwd);
    if (this.sessionAllows.has(key)) return true;
    const normalized = tool === "bash" ? normalize(content) : path.resolve(cwd, content);
    return this.permanent.some((e) => {
      if (e.tool !== tool) return false;
      const scoped = typeof e.pattern === "string" || typeof e.domain === "string";
      if (!scoped) return e.key === normalized && e.cwd === cwd;
      if (typeof e.pattern === "string" && !matchCommandGlob(e.pattern, normalized)) return false;
      if (typeof e.domain === "string" && !this.allTargetsWithinDomain(tool, content, e, cwd, analysisCwd)) {
        return false;
      }
      return true;
    });
  }

  /**
   * `domain` entries allow a command only when every filesystem target
   * resolves inside the recorded domain (lexical AND canonical — an
   * in-domain symlink pointing outside fails).  Commands with no targets
   * match only when the execution cwd itself is inside the domain.
   * Non-bash tools use their resolved subject path as the single target.
   */
  private allTargetsWithinDomain(
    tool: string,
    content: string,
    entry: AllowEntry,
    cwd: string,
    analysisCwd: string,
  ): boolean {
    const domain = semanticPathCandidates(entry.domain ?? "", entry.cwd);
    const withinDomain = (candidate: string): boolean =>
      domain.some((directory) =>
        candidate === directory ||
        candidate.startsWith(directory.endsWith("/") ? directory : `${directory}/`),
      );
    const resolvesInside = (target: string, base: string): boolean => {
      // realpath-ordered resolution, shared with permission/dd checks (R3);
      // command targets arrive already home-expanded at the quoting boundary.
      const candidates = semanticPathCandidates(target, base, { expandHome: false });
      return candidates.length > 0 && candidates.every(withinDomain);
    };

    if (tool !== "bash") {
      // The subject is a filesystem target only when the tool actually
      // operates on a single path (write/edit tools) — not for tools whose
      // subject is source code or free text (eval, notebook cells), which
      if (!looksLikeSinglePath(content)) return false;
      return resolvesInside(path.resolve(cwd, content), cwd);
    }

    const { targets, undeterminable } = commandFileTargets(content, analysisCwd);
    if (undeterminable) return false;
    if (targets.length === 0) {
      return semanticPathCandidates(cwd, cwd).every(withinDomain);
    }
    return targets.every((target) => resolvesInside(target.value, target.cwd));
  }

  /** Record a session allow. */
  rememberSession(tool: string, content: string, cwd: string): void {
    this.sessionAllows.add(makeAllowKey(tool, content, cwd));
  }

  /** Record a permanent allow (persisted to disk). */
  rememberPermanent(tool: string, content: string, cwd: string): void {
    const entry: AllowEntry = {
      tool,
      key: tool === "bash" ? normalize(content) : path.resolve(cwd, content),
      cwd,
      timestamp: new Date().toISOString(),
    };
    this.permanent = this.permanent.filter(
      (e) => !(e.tool === entry.tool && e.key === entry.key && e.cwd === entry.cwd),
    );
    this.permanent.push(entry);
    this.savePermanent();
  }
}

/** A tool subject counts as a single path only when it reads like one —
 *  no whitespace/newlines, no shell metacharacters (R2). */
function looksLikeSinglePath(content: string): boolean {
  const trimmed = content.trim();
  return (
    trimmed.length > 0 &&
    trimmed === content &&
    !/[\s;&|()<>$`"'\\]/.test(trimmed)
  );
}
