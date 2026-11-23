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

## 八、复审修正 R2（对应 REVIEW.md 返工六组项）

复审对象：`4a72d44` 之后轮次。六组结构性修正，均带正反断言。

| 组 | 修正 | 断言 |
|----|------|------|
| R1 管线相邻 | `pipeStageProgram`：每级取实际执行程序 basename；env/sudo/doas 解包到内层命令头；fetch→interpreter 改为**逐对相邻**扫描（`curl … \| cat \| sh` 不再误判）；xargs 保持其自身身份 | `remote-fetch-exec requires truly adjacent pairs`：wrapped 源（sudo/env/doas）仍硬拒、`cat` 隔开不误伤、尾接 `tee` 同裁决 |
| R2 目标提取 | `stageFileOptionTargets` + 选项表：`tar/curl/wget/find/sort/git/ssh` 等文件型选项值计入目标（`-o`/`-O`/`-K`/`-F`/`--reference` 等）；非文件选项值跳过；重定向目标逐段计入（`/dev/null` 豁免）；`scp/rsync` 远程操作数正则排除；未知命令有操作数即 `undeterminable` → 普通审批；非 bash 工具需 `looksLikeSinglePath` 才按路径处理（eval 源码不再当路径） | `domain matching handles mixed targets, spaces, links, and cwd`（域内混合目标/含空格/域外链接）；重定向目标断言在 R2/R3 追加（见 §九 复审修正 R3 片 A：`literal tilde and HOME quoting…` 重定向用例、`domain entries see sort/git file targets…`） |
| R3 路径解析 | `semanticPathCandidates` 按 realpath 逐组件顺序解析，`l/../etc/passwd`（l→/etc）判 /etc 而非词法折叠；缺失尾部保留已解析前缀；`cd` 应用一次：bash gate 新增 `analysisCwd` 钩子传“命令自身 cd 生效前”的 cwd，域提取/`commandFileTargets` 用同一 cwd | gate.test.ts `a leading cd in the bash command is applied once`：`cd l && chmod 777 f`（l→/etc）硬拒、`cd sub && chmod 777 f` 可判放行；`semantic path resolution keeps .. components` |
| R4 包装/argv | POSIX `-c` 接受组合选项簇（`bash -xc`、`sh -euc`）；ssh 远端 argv 按命令行 `join(" ")`（远端本就走 shell，不重引整体）；eval 侧 argv 数组逐元素 `quoteShellArgument` 拼接——`["printf","meeting; reboot"]` 是一个参数；`launchCommands` 以 `currentCwd`（含 `%cd`/`!cd` 转换）分析 JS spawn、`shellCwd`（段内 cd 链）分析 `!cmd`/`os.system`；`innerDenyTier` 并入 `denyTier` | `argv arrays keep argument boundaries`、`python !-shell tracks cd across segments and merges deny tiers`（`!git push -f` denyTier=true） |
| R5 glob 边界 | `matchCommandGlob` 重写：按命令段拆分；`**` 覆盖整个参数（含 `/`）但不跨空白/分隔符、`*`/`?` 不跨 `/`、空白、分隔符；`!pat` 否定按段生效——复合命令中任一段命中即拒 | `command globs reject extra command segments and honor negation`：`chmod **` 不吞多参数、`rm *; ls` 中 `!rm *` 命中 rm 段即拒 |
| R6 权限操作数 | `PERMISSION_SHORT_OPTIONS_RE` 白名单化（`-w` 等符号模式按操作数处理，不再静默丢弃目标）；`--reference`（GNU/bsd 双形）取参照文件属主：可 stat 且属主/组不同 → 硬拒，不可 stat → 可判未知；`'$HOME'`/`"~"` 单引号/字面不展开（`pathArg.literal` 贯通 cd/dd/权限目标） | `permission operands honor roles, --reference, and literal quoting`：`chmod -w /etc/passwd` 硬拒、`chmod 777 '$HOME'` 可判、`--reference /etc/hostname` 硬拒、缺失参照可判 |

**附带修复的自身缺陷**：`permissionChangeTier` 中 `--reference` 判定算出后未使用（漏 `if (refOther) return`）；`semanticPathCandidates` 尾部缺失时丢弃已解析前缀；`pathArg` 未区分双引号内 `~`（双引号下 `~` 本就不展开）。

**R2 复审修正后验证**：

```
$ bun run typecheck   # tsc --noEmit → clean
$ bun test src
 236 pass
 0 fail
Ran 236 tests across 14 files.
$ bun run build       # dist/index.js 208.87 KB
```

**偏差**：无。

## 九、复审修正 R3（对应 REVIEW.md 终审五项，DECISION 路径 c）

复审对象：`f400321`。按 DECISION.md 推荐路径 (c) 分四片交付，全部用既有基础设施（`roughTokenize`/`commandAndArgs`/`semanticPathCandidates`/`pathArg.literal`），无外部 parser。

| 片 | 修正 | 断言 |
|----|------|------|
| A（R2+R6） | `sort`/`git` 移出 `NON_FILE_COMMANDS`（表项永不可达的路由缺陷）；`fileTargetsOfInvocation` 新增 sort（操作数=输入文件）与 git（仅 `-C`/`--git-dir`/`--work-tree` 值）分支；`redirectionTargets` 返回原始 token，调用处经 `pathArg`/`expandPathTarget` 统一在引号边界展开一次；`resolveFilesystemPathCandidates`/`semanticPathCandidates` 新增 `expandHome:false`，已展开路径不再二次把字面 `~` 解析到 home 根 | `sort and git route their file targets out of the non-file table`（`sort -o out.tsv notes.tsv` → 双目标、`git -C /repo` → 单目标、`git -c` 无目标）；`domain entries see sort/git file targets and reject out-of-domain operands`；`literal tilde and HOME quoting are honored end to end`（`chmod "~"` 可判、`chmod ~` 硬拒、重定向字面量） |
| B（R3） | `semanticPathCandidates` 移至 `paths.ts` 与 `resolveFilesystemPathCandidates` 并列；`allowlist.ts` 的 `allTargetsWithinDomain`（域自身与各目标）统一改用 realpath 顺序解析 —— 权限、dd、域检查三处共享同一套"保留原始分量"解析 | `domain check resolves .. through symlinks like the filesystem does`：`a/l/../note`（l→/etc）按 realpath 落 `/note` 域外拒绝、`a/self/note` 域内放行 |
| C（R4） | `extractSpawnCommandText` 返回 `{command, position}[]`（去 Set 去重）；`pythonScan` 记录每条 `!cmd`/`%%bash` 源偏移、`codeText` 逐行占位使偏移对齐 source；`analyze` 把 cwd 操作与全部 launch 按 offset 统一交错消费 —— spawn 取其时点 cwd，后续 chdir 不改写先前裁决 | `launches before and after chdir are judged with their own cwd`：同名 spawn 出现在 chdir 两侧各自裁决、`spawn; chdir` 不受后置切换影响、`chdir; spawn` 正确硬拒 |
| D（R5） | `matchCommandGlob` 重写：先 `splitCommandSegments` + `commandAndArgs` 分词为程序级单元（含 `|`，env/包装照常跳过），再对各实参值逐一 glob（`*`/`?` 不跨 `/`、`**` 可跨；token 数必须全等）；正向须整条命令恰为一个匹配程序，否定任一程序命中即拒；`roughTokenize`/`unquoteToken` 增加反斜杠转义与双引号内 `\"` 处理，tokenizer 已移至 `paths.ts` 共用（消除 behaviors→paths 循环依赖） | `command globs tokenize arguments…`：`'a file.txt'`/`"a file.txt"`/`a\ file.txt` 三种合法表示同判、`cat *` 不吞 `a b` 双实参、`!cat *` 否定对引号/转义/复合命令均生效 |

**复审修正 R3 后验证**：

```
$ bun run typecheck   # tsc --noEmit → clean
$ bun test src
 242 pass
 0 fail
Ran 242 tests across 14 files.
$ bun run build       # dist/index.js 211.76 KB
```

**偏差**：无。

## 十、复审修正 R4（对应 REVIEW.md「第四轮 · 29006fe」W1–W4）

复审对象：`29006fe`。四项必修逐项交付；R4（eval cwd 交错）第四轮已关闭，不再重复。

| 项 | 修正 | 断言 |
|----|------|------|
| W1（glob 程序名丢路径） | `CommandInvocation` 新增 `program` 字段，保留被调用 token 的完整路径与大小写（`/usr/bin/sort`、`CURL`）；`name` 仍是分类用的小写 basename；`matchCommandGlob` 改为对 `program` 匹配而非分类视图 | `command globs distinguish full paths from same-name programs`（allowlist.test.ts）：`/usr/bin/sort` 正向规则只匹配该路径（裸 `sort`、`/opt/bin/sort` 均不匹配）；否定规则 `!/usr/bin/sort ** ** **` 拒该路径而裸 `sort`/`ls` 不受影响 |
| W2（sort 连写选项漏目标） | `stageFileOptionTargets` 识别 GNU 短选项连写值（`-oout` ≡ `-o out`，文件型/非文件型表均处理）；`redirectionTargets` 返回 `{targets, incomplete}`：`<` 输入重定向同样计入文件目标、无法识别的重定向置 `incomplete` → 域检查 `undeterminable` → 普通审批（heredoc/here-string/fd 复制无文件目标，不置位）；`commandGroups`/`splitCommandSegments` 不再把 `>&`/`<&` 的 `&` 当分隔符；`commandFileTargets` 结果按 cwd+value 去重；`stagePathArgs` 排除重定向操作符 token | `attached option values and input redirection are file targets`（behaviors.test.ts）：`-o out` 与 `-oout` 目标集相同、`sort < in.tsv` 计入输入、`cat <<EOF`/`cat <&3` 非文件目标、`cat < ` 为 undeterminable；`domain entries cover input redirection and attached output spellings`（allowlist.test.ts）：`-oout.tsv` 域内放行、`< /etc/passwd` 与 `-o/etc/x` 域外拒绝 |
| W3（文件工具提前折叠） | `semanticPathCandidates` 在分量遍历前先展开 `~`/`$HOME`（与 lexical 一致，不再产生 `cwd/~/…` 伪候选）；域根按配置语义经 `expandHomeLiteral` 展开一次后走共享解析；write/edit 域分支把原始路径+cwd 直接交共享 realpath 解析器（删除前置 `path.resolve`）；`ProtectedPathMatcher.isProtected`（index.ts:394 调用链）与 `isHardBlockedFileTarget` 同样改用 realpath 顺序解析；`expandHomeLiteral` 移至 paths.ts 共用 | `write/edit domain targets resolve .. through symlinks (no early path.resolve)`：`l/../note`（l→/etc）按 realpath 落 `/note` 域外拒绝、普通域内文件不受影响、`~` 域根正确展开且域外绝对路径拒绝 |
| W4（转义字面量回归） | `pathArg.literal` 增加前导 `\~`/`\$`（未加引号）与 `"\$`（双引号内）判定——转义与单引号同语义；仅前导位置为字面量，`~/\~x` 的 home 前缀仍展开；真 home 根保持硬阻断 | `escaped tilde and dollar literals match their quoted forms (W4)`：`chmod 777 \~` 与 `chmod 777 '~'` 行为一致（user tier、不阻断）、`chmod 777 ~` 仍硬阻断、`>\$HOME/out` 与 `"\$HOME/out"`、`>'$HOME/out'` 三者目标值一致、`>~/out` 仍展开 |

另：§八 R2 行内"见 §八 复审修正 R3 片 A"章节号已更正为 §九。

**复审修正 R4 后验证**：

```
$ bun run typecheck   # tsc --noEmit → clean
$ bun test src
 247 pass
 0 fail
Ran 247 tests across 14 files.
$ bun run build       # dist/index.js 213.61 KB
```

**偏差**：无。

## 十一、复审修正 R5（对应 REVIEW.md「第五轮终审 · f2c3771」V1–V5）

复审对象：`f2c3771`。W1/W4 已关闭；本轮 V1–V4 必修 + V5 建议项一并交付。

| 项 | 修正 | 断言 |
|----|------|------|
| V1（重定向/连写选项合并） | `redirectionTargets` 按操作数区分：`>&word`/`<&word` 仅当 word 为数字或 `-` 时是 fd 复制（无文件目标），`>&file` 按 bash 语义为写文件目标；`&>`/`&>>` 在 `commandGroups`/`splitCommandSegments` 中不再被当作命令分隔符；`>|`（noclobber 覆盖）与 `|&`（stderr 管道）在管道/分段逻辑中正确处理；`SHORT_FLAGS.sort` 表 + 逐字符 cluster 扫描（`-roout` = `-r` + `-oout`），未知 cluster 字符 → undeterminable；`stagePathArgs` 跳过 heredoc 操作符后的 delimiter 词 | `redirect operator forms: >&file vs >&N, &>, and option clusters (V1)`：`>&out.log` 计入目标、`>&2`/`2>&1`/`2>&-` 无目标、`make &>build.log` 单命令单目标、`sort -roout.tsv` 与 `-o out.tsv` 目标集相同、`sort -rx` undeterminable、`sort -rn` 正常 |
| V2（读写语义） | `redirectionTargets` 返回 `{raw, write}`：`<` 为读，`>`/`>>`/`&>`/`<>` 为写；域检查消费全部目标（真实读目标同样参与域校验），`write-sensitive-file` 循环只消费写目标；heredoc/here-string（`<<`/`<<-`/`<<<`）的 delimiter 词不是文件目标 | `redirect read/write semantics…(V2)`：`cat < /proc/uptime` 不触发 write-sensitive-file、`echo 1 > /proc/sysrq-trigger` 仍触发、fd 复制无目标、heredoc 的 delimiter/正文均非目标 |
| V3（域根展开失败） | `allTargetsWithinDomain`：`expandHomeLiteral` 返回空/undefined（空串、动态 `$VAR`、`~user`）时直接 return false → 普通审批，不再把空串交共享解析器当 cwd；`semanticPathCandidates` 空候选同样拒绝 | `unresolvable domain roots grant nothing, even from the entry cwd (V3)`：`""`/`$SOME_UNSET_VAR`/`~definitely-no-such-user-xyz` 三种域根即使从条目 cwd 调用也不授予；有效 `~` 域仍可匹配 |
| V4（~ 前缀保留分量） | `expandHomeLiteral`、`resolveFilesystemPathCandidates`、`semanticPathCandidates` 三处 `~/` 展开由 `path.join(home, rest)` 改为前缀替换（`home + rest`）——`..` 分量保留给逐分量 realpath 遍历，域根、文件工具目标、保护匹配统一 | `home-prefixed targets keep original components through symlinked dirs (V4)`：绝对、`~/`、相对三种表示对 `l/../note`（l→/etc）同判域外拒绝；真实域内文件三种表示均放行（测试构造用字符串切片而非 `path.relative`，后者会先行折叠 `..`） |
| V5（混合转义，建议项） | `pathArg`：前导转义仅覆盖一个字符——值余部仍含未转义 `$`/反引号时不冻结为字面量，回到 `expandHomeLiteral` → undeterminable | `mixed escape + dynamic remainder is undeterminable, not frozen (V5)`：`>\~$VAR` 为 undeterminable、`>\~file` 仍为字面量目标 |

**复审修正 R5 后验证**：

```
$ bun run typecheck   # tsc --noEmit → clean
$ bun test src
 252 pass
 0 fail
Ran 252 tests across 14 files.
$ bun run build       # dist/index.js 215.68 KB
```

**偏差**：无。

## 十二、复审修正 R6（对应 REVIEW.md「第六轮终审 · 5a1b18b」X1–X5）

复审对象：`5a1b18b`。V3/V4 已关闭；本轮 X1–X4 必修 + X5（V5 残留）交付。

| 项 | 修正 | 断言 |
|----|------|------|
| X1（fd vs 文件名按完整操作数） | `redirectionTargets`：`>&word`/`<&word` 仅当整个 word 为纯数字或单独 `-` 时是 fd 复制——`>&2026.log`/`2>&2026.log` 是写文件；`=` 分支限定 `--` 长选项（`--output=x`），短 cluster 中 `-oreport=1.tsv` 的 `=` 作为文件名字符进入 cluster 扫描 | `fd duplication is decided on the whole word, not the first char (X1)`：`>&2026.log`/`2>&2026.log` 计入目标、`>&2`/`2>&1` 无目标、`sort -oreport=1.tsv` 解析出 `report=1.tsv` |
| X2（`\|&` 管线相邻） | `commandGroups` 在 `&` 前为 `\|` 时不再截断——`\|&` 作为完整管道操作符与 `\|` 走同一分组，`pipeStages` 中 `\|&` 已正确跳过分隔 | `\|& is a real two-stage pipe for adjacency classification (X2)`：`printf a \|& wc -c` 与 `printf a \| wc -c` 同级分组、`printf a \|& sh` 与 `printf a \| sh` 硬阻断结论一致 |
| X3（输入重定向原名） | `-`/`~` 修饰符仅在已确认为 heredoc（`<<`/`<<-`/`<<<`）后消费；普通 `<`/`>` 操作数原样保留 | `input redirection operands keep their leading characters (X3)`：`cat < -notes.tsv` 与 `cat <-notes.tsv` 均指向 `-notes.tsv` |
| X4（字面正文不是文件/命令） | 新增 `stripHeredocBodies`：在 `analyzeCommand` 与 `commandFileTargets` 两个入口、任何分段/分类之前移除 heredoc 正文行与终止分隔词（支持引号分隔词、`<<-` 制表符剥离、同行多个 heredoc 队列）；`stagePathArgs` 的 heredoc 操作符扩展为 `<{2,3}`，here-string 实参同样跳过；正文之后的真实命令照常参与审批 | `heredoc bodies and here-strings stay data, never commands or paths (X4)`：带引号 heredoc 正文中的 `cat report.tsv` 不产生目标、正文后的 `sort real.tsv` 照常计入、`cat <<< 'meeting minutes'` 无目标、正文中的 `rm -rf /` 不产生 delete 行为 |
| X5（V5 残留） | `\~`/`~` 与 `$HOME`/`$VAR` 同参且无法保留逐字符展开语义时，`pathArg`/`expandHomeLiteral` 路径返回 undeterminable，不输出错误绝对路径 | `tilde mixed with variable in one operand is undeterminable (X5)`：`>\~$HOME/x`、`>\~/$VAR`、`>~$VAR` 均 undeterminable（`>$HOME/x\~` 的尾转义为合法字面量，正常解析，未列入） |

**复审修正 R6 后验证**：

```
$ bun run typecheck   # tsc --noEmit → clean
$ bun test src
 257 pass
 0 fail
Ran 257 tests across 14 files.
$ bun run build       # dist/index.js 216.34 KB
```

**偏差**：无。

## 十三、复审修正 R7（对应 REVIEW.md「第七轮终审 · d0ffe2e」Y1–Y3）

复审对象：`d0ffe2e`。X2/X3 已关闭；本轮 Y1/Y2 必修 + Y3（X5 非阻断残留）交付。

| 项 | 修正 | 断言 |
|----|------|------|
| Y1（按完整 shell 词实际值判 fd/文件） | `redirectionTargets` 操作数改为读取完整 shell 词（引号/非引号片段拼接），fd 判定用求值后的值 + 左侧描述符：`>"2026".log`/`>"2026.log"`/裸 `2026.log` 同目标；`>&"2"` 仍是 fd 复制；显式左描述符 + 非 fd 词（`2>&2026.log`）按 bash `ambiguous redirect` 判无效 → undeterminable，不伪造文件目标；新增 `paths.ts:evaluateShellWord` 处理混合片段，`pathArg` 与 fd 词判定统一使用 | `redirect operands are judged by evaluated word value + left fd (Y1)`：三种引号写法同目标集、`>&"2"`/`>&'1'` 无目标、`2>&2026.log` 与 `2>&"out.log"` undeterminable、无左描述符的 `>&2026.log` 仍为文件写；X1 旧断言同步按 Y1 语义更新 |
| Y2（here-string vs heredoc 队列） | `stripHeredocBodies` 正则分治：`<<<` 为 here-string（无结束词、无正文行，直接 continue 不入队），`<<`/`<<-` 为 heredoc（分隔词入队）；分隔词前允许空白、支持单/双引号分隔词 | `here-strings queue no body; heredocs allow spaced/quoted delimiters (Y2)`：`cat <<< 'meeting minutes'` 后的 `sort notes.tsv` 照常计入目标、`cat << 'EOF'`（空格+引号）正文不产生目标且后续 `sort real.tsv` 计入、`cat <<"END"` 无空格双引号同样剥离、正文 `rm -rf /` 不产生行为 |
| Y3（转义字面 + 动态尾部） | `PathArg` 新增 `dynamic` 通道：前导转义字面（`\~`/`\$`/`"\$`）与含 `$`/反引号尾部混合时置 dynamic，`expandPathTarget` 直接返回 undefined → undeterminable，不再展开成错误绝对路径 | `escaped tilde plus variable tail stays undeterminable (Y3)`：`>\~$HOME/x`、`>\~$VAR`、`>\~/${HOME}` 均 undeterminable 且无伪造目标 |

**复审修正 R7 后验证**：

```
$ bun run typecheck   # tsc --noEmit → clean
$ bun test src
 260 pass
 0 fail
Ran 260 tests across 14 files.
$ bun run build       # dist/index.js 217.66 KB
```

**偏差**：无。
