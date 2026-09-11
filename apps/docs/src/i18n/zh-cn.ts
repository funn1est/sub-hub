import type { Copy } from "./types.ts"

export const zhCn: Copy = {
  htmlLang: "zh-CN",
  ogLocale: "zh_CN",
  otherLocaleLabel: "English",
  title: "Sub Hub — 自托管订阅转换",
  description:
    "自托管 Conversion Service 与 Web Console。把选定的 VLESS、Shadowsocks、Trojan、VMess、Hysteria2 和 TUIC v5 源转换成 Mihomo、Quantumult X、sing-box、Loon、Egern 和 Surge。本项目不运营公共实例。",
  skipToContent: "跳到正文",
  brand: "Sub Hub",
  languageNav: "语言",
  tagline: "自托管 Conversion Service 与 Web Console",
  noPublicInstance: "本仓库不运营公共实例。",
  heroLead:
    "仍在演进的 Rust 转换后端，外加用来操作你自己那份 Conversion Service 的静态 Web Console。Native 与 Cloudflare Worker 共用同一套宿主中立的 HTTP 与 conversion 模块。你需要自己 clone、运行或部署。",
  ctaRepo: "源码",
  ctaReleases: "Native 二进制",
  ctaDeployHint:
    "按钮会把 Conversion 与 Console 发到同一个 Worker origin。它不收集 access token。部署完成后 GET /sub 保持匿名，直到你把 SUB_HUB_ACCESS_TOKEN 勾选 Secret 加上。",
  ctaDeployAlt: "Deploy to Cloudflare",
  inputsTitle: "输入",
  inputsLead:
    "url 接受一个或多个按顺序、用 | 分隔的源。不支持或无效的节点会被跳过；源与 config 出错则请求失败。",
  inputs: [
    {
      name: "VLESS",
      detail:
        "vless:// share URI。TCP、WebSocket、gRPC，配合 TLS 或 Reality；Vision 在 target 能保留时保留。",
    },
    {
      name: "Shadowsocks",
      detail:
        "SIP002 ss://。闭集 cipher：aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305，以及两种 2022-blake3-aes-*-gcm。simple-obfs http/tls 在多数 target 保留；Surge skip。",
    },
    {
      name: "Trojan",
      detail: "trojan://。TCP+TLS 与 WebSocket+TLS。",
    },
    {
      name: "VMess",
      detail: "vmess:// 加上 v2rayN JSON v2。其他 VMess 方言拒绝。",
    },
    {
      name: "Hysteria2",
      detail: "hysteria2:// 与 hy2://。hop、salamander、pin 按 target 的 Keep-pass。",
    },
    {
      name: "TUIC v5",
      detail: "tuic://uuid:password@host:port，query 闭集。",
    },
    {
      name: "HTTPS 订阅",
      detail:
        "内容里含上述 share URI 的远端。省略 expand 或 expand=false 时，能写远端引用的 target 会把订阅留给客户端去拉。expand=true 才内联。sing-box 在省略 expand 时仍内联。",
    },
    {
      name: "ACL4SSR config",
      detail:
        "可选的 HTTPS config= 选择一份严格 ACL4SSR INI。缺省或空的 config= 是默认 PROXY/AUTO 策略，不是 ACL4SSR profile，也不是第二套 Rule frontend。",
    },
  ],
  policyTitle: "策略与 query",
  policyItems: [
    "缺省或空的 config= 走 PROXY/AUTO（select：AUTO + 节点 + Direct，url-test AUTO，MATCH → PROXY）。",
    "expand 是已接受的 query。Web Console 开关默认打开并写入 expand=true。",
    "filename 是下载名 stem（1–64 字节）。服务补上各 target 的扩展名。省略则用 sub-hub-<target>.<ext>。",
    "GET/HEAD request-target 超过 8 KiB 返回 414。",
  ],
  outputsTitle: "客户端 target",
  outputsLead:
    "target 必须是下列精确 token。列出的是会导入该文档的流行客户端，不是额外的 HTTP token。不要把 stash、surfboard、shadowrocket 当成 target。",
  outputs: [
    {
      token: "clash / mihomo",
      format: "Mihomo YAML。clash 是 Clash 兼容名；Clash Meta 客户端通常导入 clash。",
      clients:
        "Clash Verge Rev, FlClash, Clash Meta for Android, Stash, OpenClash, Karing, Hiddify",
    },
    {
      token: "quanx",
      format: "Quantumult X conf。",
      clients: "Quantumult X",
    },
    {
      token: "singbox",
      format: "sing-box JSON。",
      clients: "SFA, SFI/SFM, GUI.for.sing-box, Throne, Karing, Hiddify, NekoBox",
    },
    {
      token: "loon",
      format: "Loon conf。",
      clients: "Loon",
    },
    {
      token: "egern",
      format: "Egern YAML。",
      clients: "Egern",
    },
    {
      token: "surge",
      format: "Surge conf。Surfboard 跟随 Surge，不支持 VLESS。",
      clients: "Surge, Surfboard",
    },
  ],
  workshopTitle: "Web Console",
  workshopLead:
    "Workshop PWA 在 apps/console。你填写 Conversion Service origin，在独立字段里放 access token，组装 GET /sub 或 GET /sub/:token，Preview 同一条 Subscription URL，再复制或下载结果。",
  workshopItems: [
    "每个平台都提供 clash://install-config。iPhone 与 iPad 还会提供 Surge、Loon、Egern、sing-box 的第一方一键导入。",
    "不增加 POST 转换，也不增加额外 query 开关。",
    "Worker 上 layout all 的同源 Console 不需要 SUB_HUB_CORS_ORIGINS。对着 loopback 的 Vite Workshop 需要。",
  ],
  runTitle: "怎么运行",
  runLead:
    "这里没有托管的 Sub Hub。要自己控机器用 Native；不想装 Rust 工具链就用 GitHub Release 二进制；要 Conversion 加 Console 就发 Cloudflare Worker。",
  runItems: [
    {
      title: "Native（开发）",
      body: "mise install，然后 cargo run --locked -p sub-hub-native。安全默认监听 127.0.0.1:25500。用 GET /version 确认。",
    },
    {
      title: "Native（GitHub Releases）",
      body: "未签名的 linux-amd64、windows-amd64、macos-arm64 压缩包。不含 Web Console，也未公证。",
    },
    {
      title: "Cloudflare Worker",
      body: "Deploy-to-Cloudflare 发布 layout all：一个 Worker，Console 资产在同一 origin。GET /version 始终公开。对外的 Worker 把 SUB_HUB_ACCESS_TOKEN 设成 Secret 后，客户端走 GET /sub/<token>。",
    },
  ],
  httpTitle: "闭集 HTTP 面",
  httpLead: "当前兼容面只包含：",
  httpRoutes: [
    "GET /version",
    "GET /sub 与 HEAD /sub",
    "配置了 SUB_HUB_ACCESS_TOKEN 时的 GET /sub/:token 与 HEAD /sub/:token",
  ],
  httpNotes: [
    "没有 POST 转换、capabilities 端点或管理 API。",
    "设置 token 后 GET /version 仍公开。错误 token：401 Unauthorized!。未设置：GET /sub 保持匿名，GET /sub/:token 返回 404 Not Found。",
    "有节点被跳过时，GET/HEAD /sub 会加 x-subconverter-skipped（响应还不是 lossy 时再加 x-subconverter-result: partial）。",
  ],
  notTitle: "不在范围内",
  notItems: [
    "本站与本仓库都不提供公共转换实例。",
    "没有 Dockerfile、docker-compose 或 GHCR 发布任务。",
    "没有 AnyTLS、WireGuard、SSR。没有第二套 Rule frontend。",
    "没有额外的 subconverter 开关（include / exclude / emoji / udp / scv / sort）。",
  ],
  licenseTitle: "许可",
  licenseBody:
    "Sub Hub 使用 GNU Affero General Public License v3.0 or later。它常作为网络服务部署；AGPL 第 13 条要求修改后对外提供网络服务的运营方向用户提供对应源码。",
  sourceLink: "对应源码",
  footerNote: "这是现行公开面的产品介绍。操作细节在 README。",
}
