# smart-approve 分类策略重构 — 实施报告

**日期**：2026-11-23
**分支**：`feat/approval-policy-redesign`（本地 commit，未 push / 未发 PR）
**依据**：`DESIGN.md` §九 5 项全部按推荐值执行
**偏差**：无（仅有 2 处实现细节的填充性修复，见"实现说明"）

---

## 一、改动清单

### 1. 行为拆分（`src/behaviors.ts`）

| 迁移项 | 实现位置 | 结果 |
|--------|----------|------|
| `permission-change` → `permission-change-system`（硬）/ `-user`（可判） | `permissionChangeTier` `behaviors.ts:755-790`，调用 `analyzeBashOperation:1292` | 系统路径（`/etc /usr /bin /sbin /var /boot /sys /proc /root /Library /System`）、home 根本身（`~`、`$HOME` 解析后、home 绝对路径）、`chown` 改其他用户属主 → 硬阻断；其余 → 可判 |
| `high-risk-executable` → 三类 | 表 `behaviors.ts:80-102`，检测 `:1136-1138` | `high-risk-net-tool`（curl/wget/openssl→可判）、`high-risk-shell-pivot`（nc/netcat/ncat/socat/telnet→硬）、`privileged-exec`（sudo/ssh/scp/osascript→可判） |
| `dd-write` 拆分 | `analyzeCommand:1207-1214` | `of=/dev/{sd*,nvme*,disk*,hd*,vd*,xvd*,mmcblk*,mapper/*,md*,sg*,st*,nst*}` → `dd-block-device`（硬）；其余 `of=` → `dd-write`（可判）。复用新提取的 `BLOCK_DEVICE_PATH_RE`（`:734`） |
| `interpreter-inline-execution` / `sensitive-working-directory` / `shutdown-reboot` | `HARD_BLOCK_BEHAVIORS` `:1072-1087` 移除 | 三者降为可判；`sensitive-working-directory` 仍由 `analyzeBashOperation:1295-1297` 发出 |
| `shutdown-reboot` headless 自动拒绝（§九-1b） | `analyzeBashOperation:1306-1312` + `bash-tool.ts:459` 传入 `ctx.hasUI` | `hasUI=false` 时置 `requiresConfirmation`，走 gate.ts 既有的 no-UI 阻断路径 |
| DENY_TIER 追加 | `DENY_TIER_BEHAVIORS:1090-1094` | `permission-change-system`、`dd-block-device`（hardBlocked 时 denyTier 恒 false，仅作 LLM 失败时 regex 兜底） |
| `chmod-sys-dir` | `HARD_BLOCK_BEHAVIORS:1082` | 复用既有未使用 ID 加入硬阻断表（当前无发射路径，等价别名兜底） |

### 2. 路径敏感（`src/paths.ts`）

- `isUserWritablePath(target, sessionCwd, home)` — `paths.ts:96-110`，按 §4.2 草图：候选路径（含 canonical）任一落在 home 或 sessionCwd 内 → true。
- `matchGlob` — `paths.ts:86`，导出供 allowlist 复用同一 glob 引擎。

### 3. allow-list 扩展（`types.ts` + `allowlist.ts`）

- `AllowEntry` 增加可选 `pattern?: string`、`domain?: string`（`types.ts:230-233`）。
- `AllowList.isAllowed`（`allowlist.ts:71-84`）：精确匹配（仍 cwd 作用域）→ `pattern` glob 匹配归一化命令 → `domain` 匹配：`domain` 条目要求**每个**路径形参解析进 domain；无路径参数时要求当前 cwd 在 domain 内（`allTargetsWithinDomain:91-116`，相对路径按运行时 cwd 解析）。`rememberPermanent` 仍记精确条目（§八：记忆不扩散），`pattern`/`domain` 为手工编写的高级条目。

### 4. LLM 提示（§九-2）

- 新 i18n 字段 `promptPrivilegedNote`（`i18n.ts:39/91/138`）。
- `gate.ts:219-221`：分析含 `privileged-exec` 时向 `behaviorLabels` 追加提权审慎标注，三条分析链路（RPC prompt、Pi classifier、OMP native judge）均经 `behaviorLabels` 自动覆盖。

### 5. 审计日志（§八）

- `gate.ts:256-258`：auto 模式判定 allow 时记 `auto-allow-reviewable behaviors=[…]`。

### 6. Eval 通道传导（必需改动，否则新行为 ID 失效/语义割裂）

- `eval-analyzer.ts`：`riskyLaunch` 仅查 `high-risk-shell-pivot`（`:1221-1224`）；`DANGEROUS_ARGUMENT_PATTERNS` 收窄为 `dd of=/dev/` 块设备、`rm -rf`、`/etc` 账号文件（`:1027-1032`）；`SHUTDOWN_CMD` 从 `hasDangerousPayload` 移除；`sensitiveCwd`/`shellSensitiveCwd` 不再计入 hardBlocked（`:1287`）。
- `eval-tool.ts:102`：`sensitiveCwd` 不再硬阻断（行为仍上报）。

## 二、实现说明（非偏差，设计留白处填充）

1. **`curl|wget … | sh` 管线**：旧代码靠 `high-risk-executable` 兜底拦截；`remote-fetch-exec` 原有 regex 只匹配 `echo|printf|fetch … | sh`，从未匹配 curl/wget 管线。降档后必须在 `behaviors.ts:1264` 显式加入 `curl|wget | interpreter` 模式，否则 §三保留的 `remote-fetch-exec` 硬阻断形同虚设。已补 + 测试覆盖（`curl x | sh`→hard、`git commit -m "curl x | sh"`→不触发）。
2. **`sudo chmod ~/x` 等包装**：初版 `sudo` 不在 `commandAndArgs` 的包装跳过列表，内部命令不参与分类。codex 复审 B1 指出这与 §3.2「残余风险由内部行为单独捕获」的承诺冲突，已在复审修正中改为解包分析（见「复审修正 B1」）。

## 三、测试

```
$ bun test src
 210 pass
 0 fail
Ran 210 tests across 14 files.

$ bun run typecheck   # tsc --noEmit → clean
$ bun run build       # Bundled 24 modules → dist/index.js 183.81 KB
```

新增/更新用例覆盖任务单第 6 项全部要求：

- 系统 vs 用户路径 chmod、home 根（`~`、`${home}`）硬阻断、`chown` 其他用户属主：`behaviors.test.ts` "permission-change splits into system (hard) vs user (reviewable)"
- 三类 executable 拆分：`"high-risk executables split into three tiers"` + `"restored categories report their specific behavior and tier"`
- dd 双路：`"dd splits by output target"`
- shutdown headless 拒绝：`"shutdown-reboot auto-rejects when headless but stays reviewable with UI"`
- pattern/domain 匹配：`allowlist.test.ts`（新建，4 个用例：精确优先、glob 匹配、domain 全路径约束、session 作用域）
- `isUserWritablePath`：`paths.test.ts`
- eval 通道同步更新：`eval-analyzer.test.ts`（spawn 拆档、cwd 可判、dd/shutdown 降档）、`gate.test.ts`（cd 敏感目录改走弹窗、`!ssh` 可判）

## 四、配置迁移（`~/.omp/agent/smart-approve.json`）

| 字段 | 原值 | 新值 |
|------|------|------|
| `autoFallback` | `"block"` | `"regex"` |
| `autoInHeadless` | `false` | `true` |
| 其余（enabled/mode/autoBlockRisk/llmAnalysis/rememberDecisions/model） | — | 不变 |

JSON 不支持注释，原值记录于此报告（任务单允许的方式）。

## 五、commit 列表（`feat/approval-policy-redesign`，本地）

- `2fbf8c08e1` feat(behaviors): split hard-block classification into tiered behaviors (DESIGN §3)
- （本报告随后单独 commit）

## 六、偏差

初版交付时自评「无偏差」；codex 独立审阅（REVIEW.md，verdict FAIL）指出 8 项必修，其中 B1/B2 与 §3.2「包装内危险命令仍被单独捕获」的承诺冲突，属于实现缺口而非设计偏差。全部 8 项及 2 项建议已按 REVIEW 的「最小修正和验收条件」返工，详见下节。

---

## 七、复审修正（对应 REVIEW.md B1–B8 + 建议项）

复审对象：初版 `2fbf8c0 + 4a72d44`。本轮修正全部落在 `feat/approval-policy-redesign` 后续 commit。

| 项 | 修正 | 验收断言（测试） |
|----|------|------------------|
| B1 Bash 包装 | `innerWrappedCommand`（`behaviors.ts`）：sudo/doas/ssh 按各自操作数文法解出内部命令文本（保留引号），POSIX shell `-c` 内联脚本同样解包；内部命令入 pending 重新分析，与外层 `privileged-exec` 标签合并取较严裁决 | `wrapped local commands merge inner hard verdicts…`（behaviors.test.ts）：`sudo rm -rf /`/`ssh host rm -rf`/`bash -c 'rm -rf /'` 硬阻断、`sudo ls` 可判；gate.test.ts：allowlist 命中仍先硬拒、headless `sudo shutdown` no-ui 且模型调用 0、`sudo ls` 走模型 |
| B2 Eval 强制裁决 | `eval-analyzer.ts`：对静态可识别 spawn 命令统一调 `analyzeBashOperation(command, base, session, {hasUI})`，合并内部 behaviors/hardBlocked/requiresConfirmation（保留 `privileged-exec` 供提权标注），`eval-tool.ts` 传入 `ctx.hasUI` | gate.test.ts：JS `Bun.$\`shutdown…\`` 与 Python `!shutdown` headless 均 no-ui、模型/委派调用 0；`chmod 777 /etc/foo` 硬拒；`!ssh host` 的 behaviorLabels 含 `promptPrivilegedNote` |
| B3 allowlist 约束短路 | `isAllowed`：带 `pattern`/`domain` 的条目必须**全部**满足；新增 `matchCommandGlob`（paths.ts）——完整命令锚定、`*`/`?` 不跨命令分隔符、`**` 可跨、`!` 否定；纯精确旧条目保持 cwd 作用域 | `combined pattern+domain entries reject single-side matches`、`exact keys outside their scope are rejected`、`command globs reject extra command segments and honor negation`（额外命令段 `chmod 600 file; rm -rf /tmp/x` 拒绝） |
| B4 域内判定 | 新 `commandFileTargets`（behaviors.ts）：按工具操作数文法提取全部目标（引号/空格/相对路径/`--reference` 等），按执行 cwd 解析；域判定改为词法+规范候选**全部**在域内（域内 symlink 指域外拒绝）；`undeterminable` 时回普通审批；非 bash 工具统一 `path.resolve(cwd, content)` | `domain matching handles mixed targets, spaces, links, and cwd`（临时目录：混合目标、含空格文件、域外链接、不同 cwd、`$UNKNOWN_VAR` 拒绝） |
| B5 权限目标 | `expandHomeLiteral` 展开 `~`/`$HOME`/`${HOME}`；`isSystemTarget` 覆盖 `/` 根目录本身；`permissionTargets` 按 chmod/chown/chgrp 操作数语义识别（`--reference` 后不再跳首个操作数）；`analyzeBashOperation` 按命令段跟踪 `cd` 后的 cwd；`semanticPathCandidates` 按 realpath 顺序解析（中间 symlink 的 `..` 不再词法折叠） | `permission targets expand HOME variables and cover the root directory`、`permission targets follow per-segment cd and symlinked system directories`（含指向 /etc 的 symlink、其他属主硬拒保留） |
| B6 下载管线 | 删除整段 regex，改按管线相邻两端实际执行程序判定：`commandGroups`（不在单 `\|` 切分）+ `pipeStages` + `commandAndArgs` basename 语义；右端解包 sudo/doas，但不解包 xargs（`… \| xargs bash -n` 固定脚本不误伤） | `remote-fetch-exec judges adjacent pipeline programs`：`/usr/bin/curl … \| /bin/bash` 硬拒、`curl --version; bash -n script.sh` 独立命令可判、commit message 仅文字不触发 |
| B7 dd 目标 | `dd of=` 在 `analyzeBashOperation` 按有效 cwd 解析全部 of= 操作数；除字面设备名外，对已存在目标用 `fs.statSync().isBlockDevice()` 判类型（可注入替身）；普通镜像文件保持可判 | `dd of= resolves against the execution cwd and checks device type`：`/dev/disk/by-id/…` 别名硬拒、相对路径 cwd 解析+元数据断言、`disk.img` 可判；不触真实设备 |
| B8 headless 有效模式 | `gate.ts`：`autoMode = mode==="auto" \|\| (!hasUI && autoInHeadless)`，置于强制确认检查之后；interactive+autoInHeadless 的 headless 可判项走模型，强制确认项仍拒，有 UI 仍弹窗 | `gate: one migrated config drives UI dialog, headless model, headless confirm reject`（同一份迁移配置三分支） |
| 建议 1 | 三路提权标注纳入现有测试 | host.test.ts 新增 3 用例：Pi classifier `state.detectedBehaviors`、OMP native judge 同字段、RPC prompt 均含 `promptPrivilegedNote`；eval gate 另有一处 |
| 建议 2 | 精确永久条目写盘形状断言 | allowlist.test.ts `rememberPermanent writes exact tool/key/cwd/timestamp entries`（键集合恰为 tool/key/cwd/timestamp） |
| 建议 3 | 硬阻断表旧注释重写；本报告「无偏差」表述修订 | `behaviors.ts` HARD_BLOCK_BEHAVIORS 注释已更新为现行分类语义 |

**返工附带修复的自身缺陷**：`&&` 分组切分的起始偏移（下一段残留 `&`）；包装解包丢失引号导致 `sudo bash -c 'rm -rf /'` 内联脚本被截断。

**复审修正后验证**：

```
$ bun run typecheck   # tsc --noEmit → clean
$ bun test src
 229 pass
 0 fail
Ran 229 tests across 14 files.
$ bun run build       # dist/index.js 199.91 KB
```
