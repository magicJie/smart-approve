# smart-approve 门收敛路径决策

日期：2026-11-23  
候选：f400321  
依据：REVIEW.md 终审节、src/behaviors.ts、src/paths.ts、src/eval-analyzer.ts、src/allowlist.ts

---

## 一、结论先行

**推荐路径：(c) 混合——保留现有字符串/正则分类层，对路径提取、参数分词、域校验三处切换至已有的 `roughTokenize`/`commandAndArgs`/`semanticPathCandidates` 基础设施。不引入外部 parser。**

五项终审缺口均可在现有基础设施内根治；根因是路由/顺序错误，不是解析能力不足。推荐路径代价最低，236 个现有测试零冲击，包体不增。

---

## 二、基座选择

### 三条路径对比

#### (a) 继续字符串级补丁 + 强化 fail-closed

每轮 codex 审阅证明这条路不收敛：补丁封堵具名示例，审阅者随即构造语义等价输入绕过。根因在于：**R2 是路由问题**（`sort`/`git` 被错放进 `NON_FILE_COMMANDS`，表项永不可达）；**R3 是调用点问题**（`allTargetsWithinDomain` 调用旧解析器）；**R4 是遍历顺序问题**（cwd 路径在所有 spawn 命令前被批量消费）；**R5 是匹配前无分词**；**R6 是 `literal` 标志未传透**。这五处都不是"字符串近似精度不够"——它们是错误路由或遗漏传播，属于正确性缺陷，不是近似缺陷。继续字符串级补丁会修症状，不修病根。

#### (b) 引入形式化 shell 词法/语法解析

候选：tree-sitter-bash（WASM，~500 KB）、bash-parser（纯 JS，~200 KB，不支持完整 POSIX）、shlex（纯 TS，~10 KB，只分词）。  
当前 bundle：`dist/index.js` 208 870 字节（208 KB）。引入 tree-sitter-bash 使 bundle 超过 700 KB，且需要 Bun bundler 对 WASM 的显式支持；bash-parser 有已知复杂语法限制；shlex 只分词，不提供 AST，对 R4（Eval 源位置）和 R3（realpath 语义）无帮助。  
**更关键的是**：五项缺口无一需要 AST——需要的是正确的分词边界（R5）、正确的 realpath 路径遍历（R2、R3）、正确的遍历顺序（R4）和正确的引号标志传播（R6）。这些需求都已被现有基础设施覆盖，只是调用方没有使用。

> **实测依据**：`resolveFilesystemPathCandidates`（`paths.ts:206`）已实现 realpath 回退；`semanticPathCandidates`（`behaviors.ts:901`）已实现逐组件顺序解析；`roughTokenize`（`behaviors.ts:1419`）已实现引号感知分词；`commandAndArgs`（`behaviors.ts:328`）已实现 `--`、赋值跳过、xargs 解包；`pathArg`（`behaviors.ts:732`）已标记单引号/双引号字面 `~`。

引入外部 parser 对收敛无贡献，但带来 bundle 成本、依赖风险和 236 个测试的大面积改写。

#### (c) 混合——路径提取/参数分词/域校验用真正的 tokenizer，行为分类仍用正则

五处缺口都在已有基础设施的正确使用路径上：

| 缺口 | 根因定位（实测） | 所需基础设施 | 是否已存在 |
|------|---------------|------------|---------|
| R2 `sort`/`git` 操作数 | `NON_FILE_COMMANDS`（`behaviors.ts:1113`）包含 `sort`、`git`，`fileTargetsOfInvocation` 中的 `NON_FILE_COMMANDS` 检查（`behaviors.ts:1245`）先于 per-name 分支，`FILE_OPTION_VALUE`（`behaviors.ts:1068`）的 `sort`、`git` 条目永不可达 | `stageFileOptionTargets`、`stagePathArgs` | ✓ |
| R3 域检查旧解析器 | `allTargetsWithinDomain`（`allowlist.ts:110`）的 `resolvesInside` 调用 `resolveFilesystemPathCandidates`（`paths.ts:206`）：先 `path.resolve` 折叠 `..`，再 realpathSync；符号链接后 `..` 的语义路径丢失 | `semanticPathCandidates`（`behaviors.ts:901`）：逐组件走文件系统 | ✓ |
| R4 Eval cwd 时序 | `eval-analyzer.ts:1253`：先通过 `extractEvalWriteTargets(...).cwdPaths` 批量消费所有 cwd 变更至 `currentCwd`，再对全部 `codeSpawns` 统一使用该终态 cwd；`extractSpawnCommandText` 返回 `Set`（`eval-analyzer.ts:1082`），去重后丢失位置信息 | 单遍按源码顺序交错处理 cwd 变更与 spawn 提取 | 需重组，逻辑已有 |
| R5 glob 文本分词 | `matchCommandGlob`（`paths.ts:95`）对整串原始命令文本做 `re.test(value)`；`compileCommandGlob` 中 `*` 编译为 `[^/\s;&\|…]*`，遇带空格的完整引用实参时失配 | `roughTokenize`（`behaviors.ts:1419`）先分词，再对各实参值匹配 | ✓ |
| R6 字面 `~` 二次展开 | `pathArg`（`behaviors.ts:732`）正确标记 `literal`；`expandPathTarget`（`behaviors.ts:1049`）对 `literal: true` 的 `PathArg` 未跳过 `expandHomeLiteral`，导致 HOME 路径进入候选 | 在 `expandPathTarget` 中用 `literal` 标志截断展开 | ✓ |

**推荐路径 (c) 的收敛预期**：每项缺口有明确的单点修正，修正后覆盖路径封闭，无法再以"下一个语义等价输入"绕过——因为修正的是路由/顺序，不是再加一条正则。

---

## 三、fail-closed 完备性

无论选哪条路，以下路径目前静默放行（不触发 `undeterminable` 或普通审批），需明确落点：

### 3.1 现在静默放行的路径

| 场景 | 当前行为 | 代码位置 | 应有落点 |
|------|---------|---------|---------|
| `sort -o out.tsv in.tsv`：sort 在 `NON_FILE_COMMANDS` | `targets=[], complete=true`，域检查只看 cwd | `behaviors.ts:1245`、`behaviors.ts:1113` | 修 R2 后提取操作数 |
| `git -C /path …`：git 在 `NON_FILE_COMMANDS` | 同上 | 同上 | 修 R2 后提取 `-C` 值 |
| `chmod "~" 0755`（双引号字面 `~`）：二次展开后按 home 根判定 | `permission-change-system`，硬拒绝 | `behaviors.ts:902`、`behaviors.ts:1034` | 修 R6 后可判（普通文件） |
| Eval JS spawn 在 `chdir` 之后出现：spawn 拿到 post-chdir cwd | 分类用错 cwd，可能漏判敏感路径 | `eval-analyzer.ts:1253`、`eval-analyzer.ts:1082` | 修 R4 后按源位置消费 |
| `chmod *` 匹配 `chmod 'a file with spaces'`：glob 文本失配 | 否定条目将失配转为允许（静默放行） | `paths.ts:95`、`paths.ts:116` | 修 R5 后对实参值匹配 |
| 未知命令、零操作数（如 `myprog`）：`stagePathArgs` 返回空 | `targets=[], complete=true`，域检查通过 | `behaviors.ts:1266–1270` | **设计意图合理**（零操作数命令无文件目标，域检查按 cwd 是正确的 fail-closed 表现） |
| Eval 动态 spawn（计算参数，非字面量）：`extractSpawnCommandText` 未捕获 | 不做 bash 分析，不触发 `eval-process-spawn` | `eval-analyzer.ts:1082` | **已有 fail-closed**：动态 spawn 不触发硬阻断，普通审批路径兜底（DESIGN §3 "无法确定 → 普通审批"） |
| shell 替换（`` `cmd` ``、`$(cmd)`）：`commandFileTargets` 设 `undeterminable=true` | 触发普通审批 | `behaviors.ts:1289` | **已正确处理** |
| `innerWrappedCommand` 返回 undefined 的包装器（如 `doas` 参数解析失败） | 设 `undeterminable=true` | `behaviors.ts:1298–1300` | **已正确处理** |

### 3.2 修正后仍需监控的静默放行

修 R2、R3、R4、R5、R6 后，唯一剩余的结构性静默放行场景是：**未知命令且零操作数**。这符合设计意图（无文件目标的操作不需要域授权），应在测试断言中明确记录为预期行为，而非遗漏。

---

## 四、逐项处置（推荐基座下）

| 项 | 能否不用 parser 根治 | 修正方案 | 单独可交付 |
|----|-----------------|---------|---------|
| R2 `sort`/`git` 操作数表不全 | ✓ | 将 `sort`、`git` 从 `NON_FILE_COMMANDS` 移除；在 `fileTargetsOfInvocation` 中为 `sort` 添加操作数处理（非选项参数为输入文件）、为 `git` 添加 `-C` 值提取；保留 `NON_FILE_COMMANDS` 中其他与文件无关的 git 子命令路径（已由 `analyzeGit` 分支处理） | ✓ |
| R3 域检查旧解析器 | ✓ | `allowlist.ts:110`：`resolvesInside` 中将 `resolveFilesystemPathCandidates(target, base)` 替换为 `semanticPathCandidates(target, base)`；域本身的解析同步切换 | ✓ |
| R4 Eval cwd 时序 | ✓（逻辑重组，非外部 parser）| `eval-analyzer.ts:1082–1253`：将 `extractSpawnCommandText` 返回的命令集合改为带源位置的有序列表；在 `analyze` 方法中与 `cwdPaths` 交错，按源码顺序消费——spawn 在 chdir 前则用 chdir 前 cwd，在 chdir 后则用 chdir 后 cwd；去掉 `Set` 去重以保留位置信息 | ✓ |
| R5 glob 实参分词 | ✓ | `paths.ts:95`：`matchCommandGlob` 对命令先调 `roughTokenize`（或 `commandAndArgs`），再将 glob 模式与实际实参值逐一匹配，而非对原始字符串做正则 | ✓ |
| R6 字面 `~` 二次展开 | ✓ | `behaviors.ts:1049`：`expandPathTarget` 在 `arg.literal === true` 时跳过 `expandHomeLiteral`，直接返回 `arg.value`；`redirectionTargets`（`behaviors.ts:613`）返回原始字符串，调用处需判断引号后再决定是否展开 | ✓ |

---

## 五、实施切片

每片独立可交付（通过 typecheck + test + build），不依赖其他片：

### 片 A：路由与表修正（R2、R6）
- `behaviors.ts`：从 `NON_FILE_COMMANDS` 移除 `sort`、`git`；在 `fileTargetsOfInvocation` 添加 `sort` 和 `git` 分支；`expandPathTarget` 加 `literal` 短路。
- 测试：`sort -o out notes.tsv` 返回两个目标；`sort` 操作数在域外拒绝域授权；`chmod '"~"' 0755` 可判；`chmod ~` 仍硬拒绝。
- 包体影响：±0 KB。

### 片 B：域解析对齐（R3）
- `allowlist.ts`：`allTargetsWithinDomain` 中 `resolvesInside` 切换至 `semanticPathCandidates`。
- 需将 `semanticPathCandidates` 从 `behaviors.ts` 导出，或将调用点移至 `behaviors.ts`，或将函数移至 `paths.ts`（推荐：移至 `paths.ts`，与 `resolveFilesystemPathCandidates` 并列）。
- 测试：同一输入在权限判断、dd、域检查三处指向同一文件；临时符号链接域内/域外各一。

### 片 C：Eval 启动时序（R4）
- `eval-analyzer.ts`：`extractSpawnCommandText` 返回 `{command: string, position: number}[]`；`analyze` 方法的 cwd 跟踪循环改为按 position 排序的统一遍历，交错处理 cwd 更新和 spawn 分析。
- 测试：chdir 前后各启动一次，断言各自裁决；追加后续 chdir 不影响先前裁决。

### 片 D：glob 实参分词（R5）
- `paths.ts`：`matchCommandGlob` 中加入实参级匹配路径；正向模式在各参数值上测试 glob（需全部匹配），否定模式在各参数值上测试（任一匹配则拒绝）。
- 测试：带空格的完整引用文件名，正向和否定规则各一；多个独立参数不被单通配符吞并。

---

## 六、总结

**推荐：路径 (c)，按片 A → B → C → D 顺序交付。**

五项缺口均是路由或顺序错误，不是字符串近似精度不足，也不需要外部 parser。现有 `roughTokenize`/`commandAndArgs`/`semanticPathCandidates`/`pathArg.literal` 基础设施已覆盖所需能力，只是调用方没有正确使用。每片修正封闭对应路径，codex 无法再以"语义等价输入"绕过——因为修正的是数据流路由，而非再追加一条匹配规则。bundle 零增长，236 个现有测试无破坏性改动。
