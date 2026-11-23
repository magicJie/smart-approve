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
2. **`sudo chmod ~/x` 等包装**：`sudo` 不在 `commandAndArgs` 的包装跳过列表，`sudo chmod ~` 分类为 `privileged-exec`（可判）而非 `permission-change-system`。这是设计的推荐语义（sudo 入可判由 LLM 评估，§九-2b 配合 prompt 提权标注），内部命令不再解包分类，与迁移前 `sudo` 一律硬阻断比是放松，但与设计一致。

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

无。第 1、2 节未偏离 DESIGN.md 任何判据；"实现说明"中的两处是设计未展开的填充性决策，方向均与设计原则一致（可疑→可判，不可逆→硬阻断）。
