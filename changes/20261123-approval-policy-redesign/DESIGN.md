# smart-approve 分类策略重构设计

**日期**：2026-11-23  
**状态**：设计草稿，待 Jay 拍板  
**仓库**：`/data/repos/magicjie/smart-approve`（当前分支：`fix/false-positive-labels`）  
**授权范围**：只读调查 + 方案，不改 `src/`

---

## 一、根因诊断

### 问题直答：模型问题还是插件逻辑问题？

**是分类粒度问题（插件逻辑），不是弹窗层问题，也不是模型问题。**

`chmod 600 ~/.draft` 被硬阻断的原因：

1. `behaviors.ts:1030` — 任何 `chmod`/`chown` 均无条件添加行为 `permission-change`  
2. `behaviors.ts:970` — `permission-change` 在 `HARD_BLOCK_BEHAVIORS` 表中  
3. `gate.ts` 决策管线（`authorize()`）：`hardBlocked === true` 时立即返回 block，**跳过 allowlist、跳过 LLM、跳过对话框**

因此 `model: openai-codex/gpt-6.1-terra` 完全没有机会被调用。调换模型不会改变任何结果。同样的逻辑适用于 `curl file.txt`（`high-risk-executable` → hard block）和 cwd 在 `/etc` 下的任何命令（`sensitive-working-directory` → `analyzeBashOperation:1156` → hard block）。

**证据类型**：实测（SessionForensics） + 代码推导（无歧义路径）。

---

## 二、目标行为模型（三档）

参照 codex 式体验：绝大多数命令无感直通，只有真正危险的才介入。

| 档位 | 触发频率 | 语义 | 行为 |
|------|----------|------|------|
| **直通（Pass-through）** | 绝大多数（>95%） | 无风险行为，或行为完全在任务域内 | 零中断，立即放行 |
| **可判（Reviewable）** | 甚少（<5%） | 有风险信号但需上下文判断；AI verdict 或弹窗 | auto 模式走 LLM 裁决；interactive 模式弹窗 |
| **硬阻断（Hard block）** | 极窄（<0.5%） | 不可逆损害，任何任务上下文均无法使其合理 | 无条件拒绝，不走 LLM，不可 allow |

**核心设计原则**：硬阻断的判据是"无论任务是什么，都不应该发生"，而不是"看起来可疑"。可疑但合法的操作属于可判档。

---

## 三、行为迁移对照表

### 3.1 现有 HARD_BLOCK_BEHAVIORS 逐项评审

（文件：`behaviors.ts:958-976`）

| 行为 ID | 当前档位 | 建议档位 | 迁移理由 | 残余风险 |
|---------|----------|----------|----------|----------|
| `recursive-force-delete` | 硬阻断 | **硬阻断**（保留） | `rm -rf` 不可逆；即使在任务域内也应弹窗确认 | 低；任务域内的删除可用 allowlist 豁免 |
| `delete-root` | 硬阻断 | **硬阻断**（保留） | `rm /` 无任何合法用途 | 无 |
| `fork-bomb` | 硬阻断 | **硬阻断**（保留） | 纯破坏，无合法形式 | 无 |
| `remote-fetch-exec` | 硬阻断 | **硬阻断**（保留） | `curl\|sh` 是供应链攻击标准形式 | 低；pattern 仅匹配 pipe-to-interpreter |
| `write-sensitive-file` | 硬阻断 | **硬阻断**（保留） | 写 `/etc/passwd`、`/etc/sudoers` 无合法 AI 任务需求 | 低 |
| `sensitive-file-reference` | 硬阻断 | **硬阻断**（保留） | 访问 `/etc/shadow` 等账号文件 | 低 |
| `write-block-device` | 硬阻断 | **硬阻断**（保留） | 裸写块设备 | 无 |
| `disk-format` | 硬阻断 | **硬阻断**（保留） | `mkfs` 不可逆 | 无 |
| `shutdown-reboot` | 硬阻断 | ⬇ **可判** | SRE 任务中重启服务器是合法操作；LLM 可判断上下文 | 中；需兜底：headless 下自动拒绝 |
| `high-risk-executable` | 硬阻断 | ⬇ **拆分**（见 §3.2） | `curl`/`wget` 极常见且合法；`ssh`/`nc` 危险性差异大 | 见 §3.2 |
| `interpreter-inline-execution` | 硬阻断 | ⬇ **可判** | `python -c 'print("hello")'` 合法常见；与 `remote-fetch-exec` 组合时已另行捕获 | 中；LLM 需评估 `-c` 内联内容 |
| `permission-change` | 硬阻断 | ⬇ **拆分**（见 §3.3） | 核心误报源；用户自己文件的 chmod 完全合法 | 见 §3.3 |
| `dd-write` | 硬阻断 | ⬇ **拆分** | `dd if=... of=file.img` 合法；`dd of=/dev/sda` 危险 | 见 §3.4 |
| `sensitive-working-directory` | 硬阻断 | ⬇ **可判** | cwd 在 `/etc` 不代表命令本身危险；LLM 有上下文 | 中；需路径校验兜底 |

### 3.2 `high-risk-executable` 拆分方案

当前检测：`behaviors.ts:85-96`，命中 `HIGH_RISK_EXECUTABLES` 表即添加行为，均进 HARD_BLOCK。

建议拆为两个行为：

**`high-risk-net-tool`（新）→ 可判**  
目标：`curl`、`wget`、`openssl`  
理由：这三个工具是 AI 编程任务的日常工具（下载依赖、HTTPS 请求、证书操作）；LLM 可通过 URL 和参数判断风险。

**`high-risk-shell-pivot`（新）→ 硬阻断**  
目标：`nc`/`netcat`/`ncat`、`socat`、`telnet`  
理由：纯网络原语，在 AI 任务场景中几乎没有合法使用；是反向 shell 的标准工具。

**`privileged-exec`（新）→ 可判**  
目标：`sudo`、`ssh`、`scp`、`osascript`  
理由：这些工具在合法任务中频繁出现（SSH 部署、sudo 安装、macOS 自动化）；但需要 AI 和用户确认。放入可判而非硬阻断，让 LLM 评估上下文。

残余风险：`sudo rm -rf /` 会被 `recursive-force-delete` 单独捕获（硬阻断）。`curl url | sh` 被 `remote-fetch-exec` 捕获（硬阻断）。`curl` 单独出现只进可判。

### 3.3 `permission-change` 拆分方案（核心修复）

当前检测：`behaviors.ts:1030` — `chmod` 或 `chown` → `permission-change` → HARD_BLOCK。

建议拆为：

**`permission-change-system`（新）→ 硬阻断**  
触发条件（推导，需实现时验证）：
- 目标路径匹配系统目录：`/etc/`、`/usr/`、`/bin/`、`/sbin/`、`/var/`、`/boot/`、`/sys/`、`/proc/`、`/root/`
- 或 `chown` 将文件所有者改为其他用户（非当前用户）

**`permission-change-user`（新）→ 可判**  
触发条件：
- 目标路径在 `$HOME/` 下，或在 session cwd 下
- `chmod` 仅改当前用户自己文件的权限位

**实现草图**（仅供参考，不改 src/）：

```typescript
// behaviors.ts:1030 附近，替换当前无条件添加逻辑
if (name === "chmod" || name === "chown") {
  const target = positional[positional.length - 1] ?? "";
  if (isSystemPath(target)) {
    behaviorSet.add("permission-change-system"); // → HARD_BLOCK
  } else {
    behaviorSet.add("permission-change-user");   // → reviewable
  }
}

function isSystemPath(p: string): boolean {
  const resolved = resolveFilesystemPathCandidates(p)[0] ?? p;
  return /^\/(?:etc|usr|bin|sbin|var|boot|sys|proc|root)(?:\/|$)/i.test(resolved);
}
```

注意：`chmod-sys-dir` 行为 ID（`behaviors.ts:26`）已在 BEHAVIORS 目录中定义，但**从未被任何检测代码发出**（推导：grep 全文无调用）。迁移时可复用该 ID 或用 `permission-change-system`。

### 3.4 `dd-write` 拆分

**`dd-block-device`（新）→ 硬阻断**：`of=` 目标匹配 `/dev/sd*`、`/dev/nvme*`、`/dev/disk*`  
**`dd-write`（保留）→ 可判**：`of=` 目标是普通文件路径

---

## 四、执行域与路径敏感

### 4.1 现状（推导）

- `paths.ts`：`resolveFilesystemPathCandidates` 解析路径候选（symlink-aware）；`ProtectedPathMatcher` 做 glob 匹配。**仅用于 write/edit/eval gate 的文件目标检查**。
- `context.ts`（`SessionContextGatherer`）：从 `sessionManager` 提取 firstUser 和 recentAssistant 供 LLM 参考。无执行域概念。
- `behaviors.ts:analyzeBashOperation`：接受 `cwd` 和 `sessionCwd`，调用 `isSensitiveWorkingDirectory` 检查 cwd 是否在系统目录内。这是仅有的"目标路径 vs 执行域"判断，且只影响 `sensitive-working-directory` 行为。
- **结论**：目前没有"命令目标路径是否在任务执行域内"的通用机制。`permission-change` 检测完全不看路径参数。

### 4.2 最小方案设计

引入一个纯函数 `isUserWritablePath(target, sessionCwd, home)`：

```typescript
// 建议放在 paths.ts
export function isUserWritablePath(
  target: string,
  sessionCwd: string,
  home = os.homedir(),
): boolean {
  const candidates = resolveFilesystemPathCandidates(target, sessionCwd);
  return candidates.some((p) =>
    isWithinDirectory(p, home) || isWithinDirectory(p, sessionCwd)
  );
}
```

**危险目标集合定义**（硬阻断路径）：

| 类别 | 匹配规则 |
|------|----------|
| 用户 home 根 | `target === home` 或 `target === "~"` 或 `target === "$HOME"`（且有 `-r`/`-f`） |
| 根目录 | `target === "/"` |
| 系统目录 | `/etc`, `/usr`, `/bin`, `/sbin`, `/var`, `/boot`, `/sys`, `/proc`, `/root`, `/Library`, `/System` |
| 任务无关目录 | 目标不在 `sessionCwd` 下，且不在 `home` 下（提示可判，不硬阻断） |

"任务无关目录"的识别规则：路径不是 sessionCwd 的子路径，也不是 home 的子路径。这类操作应进入可判档，由 LLM 结合任务上下文判断合理性，而非硬阻断。

---

## 五、auto 模式与 headless 策略

### 5.1 现状分析

当前用户配置：
```json
{
  "mode": "interactive",
  "autoInHeadless": false,
  "autoFallback": "block"
}
```

`gate.ts:authorize()` 中的 headless 逻辑：
- `hasUI === false` + `analysis.requiresConfirmation === true` → 立即 block（不论 mode）
- `hasUI === false` + `!(autoMode && autoInHeadless)` → block

因此 worker/subagent 会话（`hasUI = false`）在当前配置下：**所有触发任何行为的命令均被阻断**。这解释了自动任务中频繁卡住的现象。

### 5.2 建议策略

**交互会话（有 UI）**：保持 `mode: "interactive"`，对可判行为弹窗，对直通放行，对硬阻断无条件拒绝。

**Headless/worker 会话**：

```json
{
  "mode": "auto",
  "autoInHeadless": true,
  "autoBlockRisk": "high",
  "autoFallback": "regex"
}
```

- `autoInHeadless: true`：headless 下启用 AI 自动决策
- `autoBlockRisk: "high"`：只有 LLM 判定 high 风险才自动阻断，medium 风险自动放行
- `autoFallback: "regex"`（从 `"block"` 改回默认值）：LLM 失败时仅靠 deny-tier regex 拦截，不全面阻断

**但当前架构有限制**：mode 是全局配置，无法按会话切换。建议将 `autoInHeadless` 路径做成"headless 时自动切 auto 模式"，而不要求用户在配置中全局改 mode。这是一个待实现的配置形态改进点（见§七待拍板项）。

### 5.3 `/smart-approve` 命令面

通过 `mode-manager.ts` 在运行时切换模式，不需要重启。当前支持的操作（推导自 `config.ts:PERSISTABLE_KEYS`）：mode、autoBlockRisk、autoFallback、autoInHeadless、coverage。对于 §三中新增的行为分类，`/smart-approve` 无需改动即可适配（新行为只影响 behaviors.ts 分类）。

---

## 六、allow-list 与记忆

### 6.1 现有机制（实测 allowlist.ts）

- **session tier**：内存 Set，key = `tool::normalize(cmd)::cwd`，会话结束清除
- **permanent tier**：JSON 持久化到 `smart-approve-allow.json`，同样是精确 key 匹配
- **问题**：精确匹配，`chmod 600 ~/a.txt` 和 `chmod 600 ~/b.txt` 是两条不同记录，无法按前缀或目标域批量记忆

### 6.2 值得持久化的形状

建议 permanent 记录支持**前缀+目标域**模式：

```typescript
// 建议扩展 AllowEntry（types.ts）
interface AllowEntry {
  tool: string;
  key: string;         // 当前：精确 normalize(cmd)
  cwd: string;
  timestamp: string;
  // 新增（可选）
  pattern?: string;    // glob 前缀，如 "chmod * ~/projects/**"
  domain?: string;     // 允许的目标路径域，如 "/home/jay/projects"
}
```

匹配逻辑：先精确匹配，再 glob 前缀匹配（pattern 字段）。

### 6.3 与 OMP 任务单执行域对齐（建议接口，不要求实现）

OMP 的任务单（task spec）通常携带工作目录或仓库路径，构成本次任务的"执行域"。建议集成接口：

```typescript
// gate.ts 或 index.ts 注入点
interface TaskDomain {
  rootPath: string;         // 任务根目录，如 /data/repos/myproject
  allowedPathPrefixes?: string[];  // 额外允许的目标路径
}

// 在 AllowList.isAllowed() 中增加 domain 参数
isAllowed(tool, content, cwd, domain?: TaskDomain): boolean
```

OMP 在 `tool_call` 触发时若能将当前 task spec 的执行域注入到 `ctx.taskDomain`（类型扩展 `ExtensionCtx`），smart-approve 即可自动对域内操作降档。这不要求 OMP 侧修改存量 API，仅需在 smart-approve 注册时声明对该字段的可选依赖。

---

## 七、配置迁移建议

### 7.1 `~/.omp/agent/smart-approve.json` 目标配置（逐项）

```json
{
  "enabled": true,
  "mode": "interactive",
  "autoBlockRisk": "high",
  "autoFallback": "regex",
  "autoInHeadless": true,
  "llmAnalysis": true,
  "rememberDecisions": true,
  "model": "openai-codex/gpt-6.1-terra",
  "contextMaxChars": 3000,
  "analysisTimeoutMs": 30000,
  "rpcIdleTimeoutMs": 600000
}
```

逐项说明：

| 字段 | 当前值 | 建议值 | 变更理由 |
|------|--------|--------|----------|
| `mode` | `interactive` | `interactive` | 不变；交互会话保持弹窗透明度 |
| `autoBlockRisk` | `high` | `high` | 不变；auto 模式只在 LLM 判定 high 时阻断 |
| `autoFallback` | `block`（用户文件） | `regex` | 改回默认；LLM 失败只靠 deny-tier 拦截，避免全面阻断 worker 会话 |
| `autoInHeadless` | `false` | `true` | **关键变更**；worker 会话启用 AI 自动决策，不再全部阻断 |
| `model` | `openai-codex/gpt-6.1-terra` | 不变 | 模型本身没问题；问题在分类层，不在模型层 |

### 7.2 `/smart-approve` 使用说明

运行时切换（无需重启，通过 `mode-manager.ts` 写回 `PERSISTABLE_KEYS`）：

- `/smart-approve mode auto` — 切到自动模式（worker 任务前手动启用）
- `/smart-approve mode interactive` — 切回交互模式
- `/smart-approve risk medium` — auto 模式下把阻断阈值降到 medium（更严格）
- `/smart-approve risk high` — 恢复阈值（放宽）

### 7.3 Profile 间差异处理

**证据（推导自 `config.ts:getConfigDir()`）**：

```typescript
export function getConfigDir(): string {
  const home = process.env.HOME || os.homedir();
  const ompDir = path.join(home, ".omp", "agent");
  const piDir = path.join(home, ".pi", "agent");
  if (fs.existsSync(ompDir)) return ompDir;
  if (fs.existsSync(piDir)) return piDir;
  return ompDir;
}
```

结论：**配置是全局共享的**，解析为 `~/.omp/agent/smart-approve.json` 单一文件。smart-approve 在所有 OMP profile 中使用同一配置，无 per-profile 加载机制。`host.ts` 中也无任何 profile 参数传入的迹象（推导）。

如需 per-profile 差异，当前唯一途径是通过 `/smart-approve` 命令在进入不同任务前手动切换模式，配合 `config.ts:persist()` 写回文件。

---

## 八、风险表

| 迁移项 | 残余风险 | 兜底机制 |
|--------|----------|----------|
| `permission-change-user` → 可判 | AI 判断错误，放行危险的 `chmod 777 ~/` 类操作 | 路径检测：`~/` 根目录的权限修改仍可设为硬阻断；`rememberDecisions` 只记忆精确命令，不扩散 |
| `interpreter-inline-execution` → 可判 | AI 漏判危险内联代码（如 `python -c '...<exploit>...'`） | `remote-fetch-exec` 仍为硬阻断，覆盖 pipe-to-interpreter 场景；LLM 看到 `-c` 内容可评估 |
| `sensitive-working-directory` → 可判 | 在 `/etc` 下执行危险命令被 LLM 误判为允许 | deny-tier 仍覆盖 `git-force-push-protected`；`write-sensitive-file` 仍硬阻断 |
| `high-risk-net-tool`（curl/wget）→ 可判 | AI 允许 `curl malicious-url | sh`（但该 pattern 被 `remote-fetch-exec` 单独捕获） | `remote-fetch-exec` 是独立检测路径，优先级高于 `high-risk-net-tool`；两者可同时触发 |
| `autoFallback: "regex"` | LLM 完全失败时只靠 deny-tier；新增的可判行为不在 deny-tier 中，会被放行 | 建议将 `permission-change-system` 和 `dd-block-device` 也加入 deny-tier 作为兜底 |
| `autoInHeadless: true` | Headless worker 自动放行 LLM 判定 medium 以下的操作 | `autoBlockRisk: "high"` 保持；硬阻断档不受 auto 模式影响（先于 LLM 判断） |

**日志审计位**：`logger.ts`，每次决策在 `gate.ts:authorize()` 中均有 `logger.log()`，记录 verdict、reason、behavior label。SessionForensics 中可见历史。建议对降档行为的 auto-allow 决策额外打一条结构化日志（`reason: "auto-allow-reviewable"`），便于事后审计。

---

## 九、待 Jay 拍板的项目

以下决策会影响保护强度，设计不自行降级，列出候选请确认：

1. **`shutdown-reboot` 是否降为可判**：SRE 工作流中重启合理，但误操作代价高。候选：(a) 保持硬阻断；(b) 降为可判，headless 下自动拒绝；(c) 降为可判，全场景走 LLM。**推荐 (b)**。

2. **`sudo` 是否降为可判**：sudo 在部署脚本中常见，但是权限提升入口。候选：(a) 保持硬阻断；(b) 可判，LLM 评估目标命令。**推荐 (b)**，但需同时在 LLM prompt 中明确标注"sudo 提权需特别审慎"。

3. **`permission-change-user` 中，`chmod 777 ~/` 类根目录操作是否单独硬阻断**：候选：(a) 统一进可判，AI 负责；(b) `chmod` 目标为 `~/`（home 根）时单独硬阻断。**推荐 (b)**，收益大于成本。

4. **headless 模式配置形态**：是全局改 `autoInHeadless: true`（影响所有 worker），还是通过 OMP 任务单注入一个 per-session override。当前代码无 per-session override 机制（推导）。如需实现需评估 OMP 侧改动量。

5. **allow-list 前缀匹配**：是否实现 §6.2 的 `pattern`/`domain` 字段扩展。影响用户体验但需改 `AllowList` 和 `types.ts`。

---

*本文档基于代码静态分析（推导）和 SessionForensics 实测记录。所有"实现草图"仅供参考，不作为实施规范，实施前需补充测试用例。*
