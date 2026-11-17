# package-lifecycle-script-auditor

JavaScript npm 生命周期脚本审计库。针对 `npm install` 时间接依赖的
`preinstall` / `install` / `postinstall` / `prepare` 等钩子做**纯静态**分析：
现有锁文件校验只确认包名与版本，本库进一步回答"这些安装钩子实际能做什么"。

**绝不执行任何包脚本**，所有结论均来自对脚本文本的静态解析，并附证据位置。

## 能力

- 从 `package.json` 与 lockfile（`package-lock.json` v1/v2/v3）构建依赖图。
- 定位生命周期钩子：`preinstall`、`install`、`postinstall`、`prepare`、
  `preprepare`、`postprepare`、`prepack`、`postpack`、`prepublish`。
- 静态分析脚本调用的：
  - shell 解释器（`sh` / `bash` 及 `-c` 内联代码）
  - Node.js 运行时（`node`、`node -e` 内联求值）
  - 远程下载（`curl` / `wget` 及 URL 字面量）
  - 下载即执行管道（`curl ... | sh`，critical 级）
  - shell 重定向（`>` / `>>` 写文件）
  - 本地可执行文件（`./setup.sh`、`chmod +x` 后直接执行等）
  - 平台条件分支（`process.platform`、`uname`、`$OSTYPE`）
- 直接依赖与传递依赖保留从根包出发的完整引用链（`chain`），并检测依赖环。
- 每条 finding 携带证据：`script` 原文、`offset` 偏移、`token` 命中文本、
  所在包、钩子名与 lockfile 路径。

## 用法

```js
const { audit } = require('package-lifecycle-script-auditor');

const report = audit({
  packageJson,        // 根 package.json 对象
  lockfile,           // package-lock.json 对象
  packageManifests,   // 可选：{ "node_modules/foo": <foo 的 package.json> }
});

// report.summary   —— 统计与各严重级计数、依赖环
// report.packages  —— 每个包的钩子、能力、引用链
// report.findings  —— 扁平化的全部发现（含证据位置）
```

严重级别：`info`（构建工具等常规行为）→ `low` → `medium` → `high` → `critical`。

## 测试

```sh
node --test
```

覆盖：合法构建脚本（`node-gyp rebuild`）、远程下载执行、平台条件脚本、
脚本缺失的包、依赖环、传递依赖引用链、嵌套 `node_modules` 解析。

## 静态分析无法判定的动态行为

以下行为在**不执行脚本**的前提下无法静态确定，审计结果中会以
`external-command`、`node-eval` 等形式提示需要人工复核：

- **运行时拼接的代码与 URL**：`node -e "require(process.env.X)"`、
  变量插值出的下载地址，其真实值只在安装时存在。
- **内联求值的具体行为**：`node -e` / `sh -c` 的字符串内容不做递归解析，
  只标记"存在内联执行"这一事实。
- **下载内容的后续行为**：`curl ... | sh` 可判定为 critical，但远端脚本
  实际做什么、是否随时间/请求头变化，静态不可知。
- **本地二进制的内部行为**：`./run.bin` 被标记为本地可执行文件，
  但二进制内部的系统调用不在 JS 脚本分析范围内。
- **PATH 解析结果**：裸命令名（如 `my-cli`）解析到哪个可执行文件
  取决于安装时环境，仅标记为外部命令。
- **条件分支的实际走向**：平台/环境变量条件（`process.platform`、
  `uname`）只报告"行为随平台变化"，不预测具体走哪个分支。
- **混淆与编码载荷**：base64、十六进制编码或字符串拼接混淆的命令
  无法还原，只能依赖 `node-eval` / `shell-inline-code` 等间接信号。
- **缺失清单的包**：lockfile 不含 `scripts` 字段；未提供
  `packageManifests` 的包会标记 `missingScripts` 并注明无法审计，
  而不是假设其无害。
