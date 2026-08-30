# Sub Hub

[English](README.md) | 中文

Sub Hub 是用 Rust 实现的、仍在演进的订阅转换后端，外加用来操作自托管
Conversion Service 的静态 Web Console。它接受选定的 VLESS、Shadowsocks、
Trojan、VMess、Hysteria2 和 TUIC v5 输入，可以加载 HTTPS 订阅资源和严格的
ACL4SSR 配置，并渲染 Mihomo（Clash 兼容）、Quantumult X、sing-box、Loon、
Egern 和 Surge 的配置。

Native 服务与 Cloudflare Worker 共用同一套宿主中立的 HTTP 与 conversion
模块。本仓库不运营公共 Sub Hub 实例；你必须自己运行或部署一份。

漏洞报告与部署方假设见 [Security](SECURITY.md)。本地门禁与当前公开
HTTP 面见 [Contributing](CONTRIBUTING.md)。这两份仍是英文原文。

Work-in-progress 指 HTTP 面是封闭的，不是自托管还没做完。本仓库不运营
公共实例。

## 运行

```sh
git clone https://github.com/funn1est/sub-hub
cd sub-hub
mise install
cargo run --locked -p sub-hub-native
```

安全默认监听地址是 `127.0.0.1:25500`：

```sh
curl http://127.0.0.1:25500/version

curl --get http://127.0.0.1:25500/sub \
  --data-urlencode 'target=clash' \
  --data-urlencode 'url=vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha' \
  --output sub-hub-mihomo.yaml
```

## 当前 HTTP 面

当前兼容面只包含：

- `GET /version`
- `GET /sub` 与 `HEAD /sub`
- 配置了 `SUB_HUB_ACCESS_TOKEN` 时的 `GET /sub/:token` 与 `HEAD /sub/:token`

`/sub` 要求 `target` 精确为 `clash` 或 `mihomo`（Mihomo YAML）、`quanx`
（Quantumult X）、`singbox`（sing-box JSON）、`loon`（Loon）、`egern`
（Egern YAML）或 `surge`（Surge）。Surfboard 导入 `surge`。Stash、Clash
Verge Rev、FlClash、Clash Meta for Android 和 OpenClash 导入 `clash`
（或 `mihomo`）。Karing 和 Hiddify 导入 `clash` 或 `singbox`。Quantumult X、
Loon 和 Egern 使用各自的 token。不要添加 `stash`、`surfboard` 或
`shadowrocket`。`url` 接受一条或多条按 `|` 分隔的有序输入：受支持的
share URI（VLESS、Shadowsocks、Trojan、v2rayN JSON v2 VMess、Hysteria2
`hysteria2://` / `hy2://`、TUIC v5 `tuic://uuid:password@host:port`），
或原始/Base64 内容含这些 URI 的 HTTPS 订阅 URL。GET/HEAD 的
request-target 超过 8 KiB 返回 414。远程、解码和节点预算仍失败关闭，
正文为 `Resource limit exceeded!`。可选的 HTTPS `config` 选择一份严格
ACL4SSR INI 及其远程 Rule Set。缺省或空的 `config=` 使用默认 PROXY/AUTO
策略；那不是远程 Rule frontend。省略 `expand` 或设 `expand=false` 时，
在能点名远程引用的 target 上把 HTTPS 订阅和 Online Rule Set 留给客户端：
`clash`/`mihomo`（`proxy-providers` / `rule-providers`）、`egern`
（`external` / `rule_set`）、`loon`（`[Remote Proxy]` / `[Remote Rule]`）、
`surge`（`policy-path=` / `RULE-SET`），以及 `quanx` 订阅
（`[server_remote]`）。Quantumult X 远程资源默认是 QX snippet；Loon 对
通用 Clash YAML 或 Base64 share-URI 容器可能需要客户端
`resource-parser`。Sub Hub 不发出该 parser。`quanx` 仍会内联 ACL4SSR
Online `.list`（Clash `DOMAIN-SUFFIX` 不是 QX `HOST-SUFFIX`；没有
`[filter_remote]`）。显式 `expand=true` 仍经 Unique-flight 内联远程。
Web Console 开关默认打开并写入 `expand=true`。省略 `expand` 时
`singbox` 仍会内联。未展开的 HTTPS 订阅用 URL 的 host 命名
（`panel.example.com`）；同一 host 再次出现才加 `-2`、`-3`。share URI
始终内联，不占这个名字。可选的 `filename` 是下载名词干（1–64 字节，不含
路径字符），服务按 target 补扩展名；省略则仍是 `sub-hub-egern.yaml` 等默认名。
`URL-REGEX` 只发给 Loon 和 Surge，其他 target 省略。
Surge 跳过全部 VLESS 节点（手册没有 `vless` 类型）。经 `policy-path=`
点名的通用 share-URI 或 Clash YAML 远程可能在客户端失败；Sub Hub 不增加
第二次转换 hop。Quantumult X 跳过 gRPC、无 Reality 的 VLESS Vision、
`auto`/`zero` VMess，以及全部 Hysteria2 和 TUIC 节点，并省略
process-name 规则。sing-box 省略 GeoIP CN，把 fallback 映射为 `urltest`、
load-balance 映射为 `selector`，并跳过 Hysteria2 gecko 与 `pinSHA256`。
Loon 跳过 gRPC、不成对的 Vision/Reality、Trojan Reality、hop/pins/gecko
以及全部 TUIC 节点，省略 process-name 规则，并把 load-balance 映射为
`pcc`。Egern 跳过 Trojan gRPC、明文 VMess gRPC、Hysteria2 gecko 和非默认
TUIC congestion，省略 process-name 规则，并把 url-test 映射为
`auto_test`。VLESS WebSocket+Reality 在每个 target 上都是解析拒绝；
Trojan WebSocket+Reality 在 Egern 上保留。Console 列出 ACL4SSR `master`
上的 33 份 INI
（`https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/`）：
18 份 Online 加 15 份 Classic / 其他。该分支会变动。把生成的 Egern 文件
导入商店版 Egern 2.20.0 以确认能解析；没有官方 `egern check` CLI。

服务目前不暴露 POST 转换、capabilities 或管理 API。可选的
`SUB_HUB_ACCESS_TOKEN` 最多容纳八个等价 path token，配置后保护
`GET`/`HEAD /sub/:token`；`GET /version` 始终公开。不支持或无效的单个
节点会被跳过，但源/容器/config 错误仍是致命的，没有任何有效节点的请求
会失败。只要有节点被跳过，`GET`/`HEAD` `/sub` 会加上
`x-subconverter-skipped`（若响应还不是 `lossy`，再加
`x-subconverter-result: partial`）。所有远程资源都经过共享的有界 SSRF
broker。内置 PROXY/AUTO 探测主机（`BUILTIN_AUTO_PROBE_URL`，
`https://www.gstatic.com/generate_204`）以及 ACL4SSR Classic 本地路径
改写到 `raw.githubusercontent.com` 是刻意的产品常量，不是测试 fixture。

## 运行 Native 后端

标签等于 `v` 加工作区版本的 GitHub Release 会附带 linux-amd64、
windows-amd64 和 macos-arm64 的未签名 Native 二进制。解压后运行
`sub-hub-native`（Windows 上是 `sub-hub-native.exe`）。这些下载是为了
在没有 Rust 工具链时也能运行；它们未签名、未经公证，不含 Web Console，
并可能被 SmartScreen 或 Gatekeeper 拦截。

工作区钉在 Rust 1.97.1。用下面命令启动开发构建：

```sh
cargo run --locked -p sub-hub-native
```

安全默认监听地址是 `127.0.0.1:25500`。用下面命令验证，并转换一条直接
share URI：

```sh
curl http://127.0.0.1:25500/version

curl --get http://127.0.0.1:25500/sub \
  --data-urlencode 'target=clash' \
  --data-urlencode 'url=vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha' \
  --output sub-hub-mihomo.yaml
```

构建优化可执行文件：

```sh
cargo build --locked --release -p sub-hub-native
```

CI 会在回环端口启动该 release 二进制，并对每个已发布 target（`clash`、
`mihomo`、`quanx`、`singbox`、`loon`、`egern`）检查 `/version` 加一次
本地 VLESS 转换。该 fixture 不拉取外部订阅。`main` 上的工作区版本 bump
会发布同样的 linux-amd64、windows-amd64 和 macos-arm64 release 可执行文件。

## Rust 开发

`mise.toml` 钉住带 `rustfmt`、Clippy 和 `wasm32-unknown-unknown` 的
Rust 1.97.1。`mise install` 通过 rustup 安装该工具链。
`rust-toolchain.toml` 使用同一钉，使 rustup 和 rust-analyzer 无需额外
环境变量即可选中它。

`rustfmt.toml` 固定 Rust 2024 style edition 与 Unix 换行；workspace
lint 政策仍集中在 `Cargo.toml`，`.cargo/config.toml` 含 Wasm 测试运行器
和按 target 的 `getrandom` 配置。

在仓库根运行全仓库 Rust 门禁：

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo check --locked -p sub-hub-conversion --target wasm32-unknown-unknown
cargo check --locked -p sub-hub-http --target wasm32-unknown-unknown
```

本地应用格式化时用没有 `--check` 的 `cargo fmt --all`。GitHub 的 `CI`
workflow 每个 revision 跑一遍这些全仓库门禁和 Worker 一致性；单独的
Mihomo workflow 只覆盖钉住的两版本外部验收矩阵。

## Native 部署边界

Native 宿主读取五个可选环境变量：

- `SUB_HUB_BIND` 设置监听地址，默认 `127.0.0.1:25500`。
- `SUB_HUB_SELF_HOSTS` 是逗号分隔的规范 DNS 别名列表，远程加载必须把
  它们拒绝为自指向。
- `SUB_HUB_ACCESS_TOKEN` 是逗号或换行分隔的列表，最多八个 unreserved
  path token（`A–Z a–z 0–9 - . _ ~`，每个 1–128 字节）。在回环上未设置时，
  `GET /sub` 保持匿名，进程会打印警告。非回环绑定且列表为空则拒绝启动。
  设置后客户端必须调用 `GET /sub/<token>`。
- `SUB_HUB_CORS_ORIGINS` 是逗号或换行分隔的列表，最多八个精确 Console
  origin（`https://console.example`、`http://localhost:5173`）。未设置则
  不发 CORS 头。已出现但为空或无效的列表拒绝启动。对着回环的 Vite
  Workshop 需要 `http://localhost:5173,http://127.0.0.1:5173`。
- `SUB_HUB_CONSOLE_ROOT` 是已构建 Web Console 目录的路径
  （`apps/console/dist`）。未设置则 Native 只做 Conversion Service。
  已设置但不是可读目录则拒绝启动。设置后，不是 `/version`、`/sub` 或
  `/sub/:token` 的 GET/HEAD 路径从该树提供文件（`/` 与未知路径回退到
  `index.html`）。同 origin 的 Preview 不需要 CORS。

除非 `SUB_HUB_SELF_HOSTS` 至少含一个主机名，非回环的 `SUB_HUB_BIND`
会被拒绝。即使反向代理转到回环监听，也要列出每一个额外部署别名。

Native 二进制有意不终止 TLS，也不提供部署级限流。网络部署时，把它放在
成熟的反向代理后面，由代理提供这些控制、强制请求与并发上限，并关闭或
脱敏 query-string 访问日志。订阅和 config URL 通常含凭证；不要直接暴露
25500 端口，也不要记录完整请求 URL。向非回环监听发送真实订阅 URL 之前，
先设置 `SUB_HUB_ACCESS_TOKEN`。

## Cloudflare Worker

Worker 在 [`crates/sub-hub-worker`](crates/sub-hub-worker)。部署你自己的
副本；本仓库不运营公共实例。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/funn1est/sub-hub)

该按钮把本仓库克隆到你的 GitHub 或 GitLab 账号，并从**仓库根**跑
Workers Builds（layout `all`：Conversion 与 Console 同一 origin）。
Cloudflare 要求该 Git URL 为 **public**。提示时把 `SUB_HUB_ACCESS_TOKEN`
设为 Cloudflare **secret**；不要把 `.dev.vars.example` 复制成
`.dev.vars`。该 secret 未设置时，Worker 的 `GET /sub` 保持匿名。Native
非回环仍会在没有 token 时拒绝启动。`GET /version` 无论哪种情况都公开。
该按钮不是项目托管的实例。

从已有机器发布时，需要一个 Cloudflare 账号、带
`wasm32-unknown-unknown` 的 Rust 1.97.1、Node.js 24.19.0 或更新，以及
钉住的 `worker-build` 0.8.5。

```sh
cargo install worker-build --version 0.8.5 --locked
cd crates/sub-hub-worker
pnpm install --frozen-lockfile
pnpm exec wrangler login
pnpm run build
pnpm run test:host
pnpm run deploy
```

`pnpm run deploy` 是 `all` layout：一个 Worker，Console 资源在同一
origin。这符合 Cloudflare Workers Free（压缩脚本小于 3 MB gzip；静态
资源是单独的免费额度）。打开打印出的 `*.workers.dev` URL，把 access
token 贴进页面。

仅 Conversion：`pnpm run deploy:worker`。仅 Console：
`pnpm run deploy:console`（然后在 Conversion 上用 `--cors-origin` 设置
`SUB_HUB_CORS_ORIGINS`）。不要提交 `account_id`、API token、本地
`name` 改名，或带真实值的 `.dev.vars`。`crates/sub-hub-worker` 里的
`.dev.vars.example` 只是按钮 schema；不要复制它。用
`CLOUDFLARE_WORKER_NAME` 或 `--worker-name` 覆盖 Worker 名；除非你打算
让每个克隆都用那个默认名，否则不要改已提交的 name。

`pnpm run deploy` 会保留已有的 `SUB_HUB_ACCESS_TOKEN` secret，或写入你用
`--tokens-file` 传入的列表，或生成一个 token 并只打印一次。把该值放进
密码管理器；Cloudflare 保存后无法再显示。不要把 token 写进已提交的
`wrangler.toml`。客户端使用 `GET /sub/<token>?target=clash&url=...`。
`GET /version` 保持公开。同 origin Console 不需要 `SUB_HUB_CORS_ORIGINS`。
额外 DNS 别名（自定义域名加上 `*.workers.dev`）可以列入
`SUB_HUB_SELF_HOSTS`；只有一个主机名时不需要该变量。

在不拉取外部订阅的情况下对已部署 origin 做 smoke：

```sh
curl "$WORKER_URL/version"

curl --get "$WORKER_URL/sub/<token>" \
  --data-urlencode 'target=clash' \
  --data-urlencode 'url=vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha' \
  --output sub-hub-mihomo.yaml
```

CI 里的 Miniflare/workerd 一致性不是生产运行时。发 release 之前，上传
一份 preview，并对该 preview URL 跑同样的 smoke：

```sh
cd crates/sub-hub-worker
pnpm run preview -- --preview-alias <preview-alias>
```

CI 不持有 Cloudflare 凭据，也不部署。Worker 把出站 HTTPS 资源限制在
443 端口。运行时边界、变量设置和不可提交项见
[Worker 部署说明](crates/sub-hub-worker/README.md)（英文）。

### Cloudflare Git

把仓库接成一个 Worker（Workers Builds，根目录
`crates/sub-hub-worker`）。该发布包含 Web Console。克隆根是整个仓库时
（本节开头的 Deploy-to-Cloudflare 按钮），仓库根 `package.json` 的
`build` / `deploy` 脚本会调用同一套 helper。构建镜像有 Node 没有 Rust；
Build 命令用 `sh scripts/install-workers-toolchain.sh`，Deploy 命令用
`sh scripts/workers-builds-deploy.sh`。这些脚本安装 Rust 1.97.1、
`wasm32-unknown-unknown` 和 `worker-build` 0.8.5，构建 Console，并运行
`wrangler deploy --keep-vars`。Dashboard 里的 Worker 名必须与
`wrangler.toml` 一致（`sub-hub`）。

Workers Builds 不跑 `mise`。若镜像较旧，把项目上的 `NODE_VERSION` 和
`PNPM_VERSION` 设成仓库根 `mise.toml` 里的钉。不要添加 `.node-version`
或 `.nvmrc`。第一次构建成功后，把 `SUB_HUB_ACCESS_TOKEN` 设为
**secret**（不是 var）。Workers Builds 不会写入该 secret；未设置时
`GET /sub` 保持匿名。不要在 Workers Builds 上用 `pnpm run deploy`
（`CI=true` 会拒绝）。仅 Conversion 的 Git 使用
`sh scripts/workers-builds-deploy.sh worker`。仅 Console 的 Git 是第二个
Worker，根目录为 `apps/console`。本机 `pnpm run deploy` 仍是更简单的
发布方式。

## Web Console

Workshop PWA 在 [`apps/console`](apps/console)。它指向你输入的
Conversion Service origin，在独立字段收集 access token，组装
`GET /sub` 或 `GET /sub/:token`，预览同一条 Subscription URL，并复制或
下载结果。它不增加 POST 转换或额外 query 开关。

```sh
cd apps/console
pnpm install --frozen-lockfile
pnpm test
pnpm run dev
```

热重载是该 Vite 进程加 Native。在仓库根另开一个终端：

```sh
SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 \
  cargo run --locked -p sub-hub-native
```

把 Workshop origin 设为 `http://127.0.0.1:25500`。已部署 Worker 上的
layout `all` 是同 origin，不需要 CORS。CI 构建并测试 Console，不部署。
见 [Console 说明](apps/console/README.md)（英文）。

## 兼容性与来源

Sub Hub 是基于公开协议规范与互操作研究的 Rust 实现。可能查阅相关开源
项目以理解生态行为。提及另一项目并不意味着源码派生、可替换兼容、隶属
或背书。

相关公开参考包括：

- [`tindy2013/subconverter`](https://github.com/tindy2013/subconverter)
- [Shadowsocks SIP002 URI scheme](https://shadowsocks.org/doc/sip002.html)
- [Shadowsocks 2022 Edition](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md)
- [VMessAEAD / VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716)
- [The Trojan Protocol](https://trojan-gfw.github.io/trojan/protocol)

第三方依赖或纳入材料仍受各自许可与声明约束。纳入材料的声明集中在
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。

## 许可

Sub Hub 以 [GNU Affero General Public License v3.0 or later](LICENSE)
授权。它通常作为网络服务部署；AGPL 第 13 条要求修改后的面向网络版本的
运营方向其用户提供对应源码。商业使用在 AGPL 下仍被允许。

漏洞报告见 [SECURITY.md](SECURITY.md)，开发门禁见
[CONTRIBUTING.md](CONTRIBUTING.md)。
