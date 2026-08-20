import type { KnownServiceError, SkipCounts } from "./service-contract.ts"
import type { PasteWarning } from "./workshop.ts"
import type { Locale } from "./persist.ts"

const ERROR_TITLES: Record<Locale, Record<KnownServiceError, string>> = {
  en: {
    "Invalid target!": "Invalid target",
    "Invalid request!": "Invalid request",
    "No nodes were found!": "No nodes were found",
    "Resource limit exceeded!": "Resource limit exceeded",
    "Unauthorized!": "Unauthorized",
    "Not Found": "Not found",
    "Method Not Allowed": "Method not allowed",
    "URI Too Long": "URI too long",
    "Bad Gateway": "Bad gateway",
    "Gateway Timeout": "Gateway timeout",
    "Internal Server Error": "Internal server error",
  },
  zh: {
    "Invalid target!": "无效的 target",
    "Invalid request!": "无效的请求",
    "No nodes were found!": "没有找到有效节点",
    "Resource limit exceeded!": "超出资源上限",
    "Unauthorized!": "未授权",
    "Not Found": "未找到",
    "Method Not Allowed": "方法不允许",
    "URI Too Long": "URI 过长",
    "Bad Gateway": "网关错误",
    "Gateway Timeout": "网关超时",
    "Internal Server Error": "内部服务器错误",
  },
}

export const messages = {
  en: {
    title: "Sub Hub Console",
    tagline:
      "Assemble sources, preview the Conversion Service response, and emit a Subscription URL.",
    language: "Language",
    theme: "Theme",
    themeSystem: "System",
    themeLight: "Light",
    themeDark: "Dark",
    service: "Conversion Service",
    serviceDescription:
      "The origin the Console calls. This is not a Subscription URL.",
    serviceOrigin: "Origin",
    serviceOriginHint:
      "Absolute http(s) origin, for example http://127.0.0.1:25500",
    accessToken: "Access token",
    accessTokenHint:
      "Empty uses /sub. A value becomes /sub/<token>. Never placed in the Console address bar.",
    showToken: "Show token",
    hideToken: "Hide token",
    versionChecking: "Checking /version…",
    versionOk: "Conversion Service",
    versionIssue: "Unreachable",
    versionOther: "This origin is not a Sub Hub Conversion Service.",
    versionUnreachable:
      "This origin did not allow the Console to read /version. Set SUB_HUB_CORS_ORIGINS on the Conversion Service to this Console origin.",
    sources: "Sources",
    sourcesDescription:
      "One to five ordered rows. Each row is one share URI or one https:// subscription URL. Duplicates are kept.",
    sourceN: "Source",
    addSource: "Add source",
    removeSource: "Remove",
    options: "Options",
    target: "Target",
    config: "ACL4SSR config",
    configNone: "No remote config",
    configOnline: "Online",
    configMini: "Mini",
    configFull: "Full",
    configCustom: "Custom URL",
    configUrl: "Config URL",
    configHint:
      "Empty omits config= and uses PROXY/AUTO. Listed files are fetched from ACL4SSR master and may change.",
    configEmpty: "No matching config.",
    appendInfo: "Append subscription-userinfo",
    appendInfoHint:
      "On by default for a single remote source. Turning this off sends append_info=false. Mihomo still sends profile-update-interval: 24.",
    subscription: "Subscription URL",
    subscriptionDescription:
      "The importable URL a client fetches. Preview uses this exact URL.",
    copyUrl: "Copy URL",
    copied: "Copied",
    copyFailed: "Could not copy",
    pasteUrl: "Import Subscription URL",
    pasteUrlHint:
      "Paste a /sub or /sub/<token> URL to fill the form. This field is not the Console location.",
    import: "Import",
    importInvalid: "That is not a Conversion Service Subscription URL.",
    overLimit:
      "This GET target is 8 KiB or larger. Preview is blocked; the Conversion Service will return 414.",
    preview: "Preview",
    previewBlocked:
      "Complete the origin, token, and at least one source before Preview.",
    previewing: "Previewing…",
    download: "Download",
    clashInstall: "Open in Clash",
    secretWarning:
      "Preview bodies contain node credentials. They stay in memory only and are not written to localStorage.",
    truncated: "Truncated in view. Download still uses the full fetched body.",
    skipped: "Skipped nodes",
    status: "Status",
    headers: "Headers",
    body: "Body",
    unreachableCors:
      "The Console could not read this Conversion Service (CORS, network, or the request was blocked). This is not an Unauthorized response.",
    unreachableMixed:
      "The browser blocked this as mixed content. Use an https Conversion Service, or a loopback http origin such as http://127.0.0.1:25500.",
    unreachableLna:
      "The browser did not allow this page to reach a loopback Conversion Service. Grant local network access if prompted, and set SUB_HUB_CORS_ORIGINS.",
    pwaUpdate: "A new Console version is ready.",
    pwaReload: "Reload",
    agpl: "Licensed under AGPL-3.0-or-later. This repository does not operate a public instance.",
    pasteWarnings: {
      "unknown-keys":
        "Unknown query keys were ignored and will not be copied onto a new URL.",
      "duplicate-keys":
        "Duplicate query keys were ignored after the first value.",
      "invalid-target": "The pasted target is not a released token.",
      "invalid-token":
        "The pasted path token is not valid AccessToken grammar.",
      "invalid-append-info": "The pasted append_info value was ignored.",
      "invalid-insert":
        "The pasted insert value was ignored; insert is never reassembled.",
      "empty-sources":
        "Empty url slots were ignored and will not be copied onto a new URL.",
      "http-sources":
        "http:// subscription sources are rejected by the Conversion Service and will not emit a Subscription URL.",
    } satisfies Record<PasteWarning, string>,
  },
  zh: {
    title: "Sub Hub Console",
    tagline:
      "组装源与选项、预览 Conversion Service 响应，并导出 Subscription URL。",
    language: "语言",
    theme: "主题",
    themeSystem: "跟随系统",
    themeLight: "浅色",
    themeDark: "深色",
    service: "Conversion Service",
    serviceDescription: "Console 调用的 origin，不是 Subscription URL。",
    serviceOrigin: "Origin",
    serviceOriginHint: "绝对 http(s) origin，例如 http://127.0.0.1:25500",
    accessToken: "Access token",
    accessTokenHint:
      "留空使用 /sub。填写后成为 /sub/<token>。不会进入 Console 地址栏。",
    showToken: "显示 token",
    hideToken: "隐藏 token",
    versionChecking: "正在检查 /version…",
    versionOk: "Conversion Service",
    versionIssue: "无法连接",
    versionOther: "这个 origin 不是 Sub Hub Conversion Service。",
    versionUnreachable:
      "这个 origin 未允许 Console 读取 /version。请在 Conversion Service 上把本 Console origin 写入 SUB_HUB_CORS_ORIGINS。",
    sources: "源",
    sourcesDescription:
      "1 到 5 行，按顺序。每行是一条 share URI 或一个 https:// 订阅 URL。重复会保留。",
    sourceN: "源",
    addSource: "添加源",
    removeSource: "删除",
    options: "选项",
    target: "Target",
    config: "ACL4SSR 配置",
    configNone: "无远端配置",
    configOnline: "Online",
    configMini: "Mini",
    configFull: "Full",
    configCustom: "自定义 URL",
    configUrl: "配置 URL",
    configHint:
      "留空则不发送 config=，使用 PROXY/AUTO。列表中的文件从 ACL4SSR master 拉取，内容可能变化。",
    configEmpty: "没有匹配的配置。",
    appendInfo: "附加 subscription-userinfo",
    appendInfoHint:
      "单个远端源时默认开启。关闭时发送 append_info=false。Mihomo 仍会发送 profile-update-interval: 24。",
    subscription: "Subscription URL",
    subscriptionDescription:
      "客户端导入的转换 URL。Preview 会 GET 同一条 URL。",
    copyUrl: "复制 URL",
    copied: "已复制",
    copyFailed: "无法复制",
    pasteUrl: "导入 Subscription URL",
    pasteUrlHint:
      "粘贴 /sub 或 /sub/<token> URL 以回填表单。此框不是 Console 地址栏。",
    import: "导入",
    importInvalid: "这不是 Conversion Service 的 Subscription URL。",
    overLimit:
      "这条 GET 目标已达到或超过 8 KiB。Preview 已阻止；Conversion Service 会返回 414。",
    preview: "Preview",
    previewBlocked: "请先填好 origin、token 和至少一条源，再 Preview。",
    previewing: "正在 Preview…",
    download: "下载",
    clashInstall: "在 Clash 中打开",
    secretWarning:
      "Preview 正文含有节点凭据。只留在内存中，不会写入 localStorage。",
    truncated: "页内展示已截断。下载仍使用完整 fetch 正文。",
    skipped: "已跳过的节点",
    status: "状态",
    headers: "响应头",
    body: "正文",
    unreachableCors:
      "Console 无法读取这个 Conversion Service（CORS、网络或请求被拦截）。这不是 Unauthorized 响应。",
    unreachableMixed:
      "浏览器按混合内容拦截了这次请求。请使用 https Conversion Service，或 loopback 的 http origin（例如 http://127.0.0.1:25500）。",
    unreachableLna:
      "浏览器不允许此页面访问 loopback Conversion Service。如有本地网络访问提示请允许，并设置 SUB_HUB_CORS_ORIGINS。",
    pwaUpdate: "有新的 Console 版本可用。",
    pwaReload: "重新加载",
    agpl: "以 AGPL-3.0-or-later 许可。本仓库不运营公共实例。",
    pasteWarnings: {
      "unknown-keys": "未知 query 键已被忽略，不会复制到新 URL。",
      "duplicate-keys": "重复的 query 键只保留第一次出现的值。",
      "invalid-target": "粘贴的 target 不是已释放的 token。",
      "invalid-token": "粘贴的 path token 不符合 AccessToken 语法。",
      "invalid-append-info": "粘贴的 append_info 值已被忽略。",
      "invalid-insert": "粘贴的 insert 值已被忽略；assemble 从不写出 insert。",
      "empty-sources": "空的 url 槽已被忽略，不会复制到新 URL。",
      "http-sources":
        "Conversion Service 拒绝 http:// 订阅源，不会发出 Subscription URL。",
    } satisfies Record<PasteWarning, string>,
  },
} as const

export type Messages = (typeof messages)[Locale]

export function t(locale: Locale): Messages {
  return messages[locale]
}

export function knownErrorTitle(
  locale: Locale,
  body: KnownServiceError
): string {
  return ERROR_TITLES[locale][body]
}

export function skippedSummary(locale: Locale, counts: SkipCounts): string {
  const parts: string[] = []
  if (counts.parse > 0) {
    parts.push(
      locale === "zh"
        ? `解析失败 ${counts.parse}`
        : `${counts.parse} could not be parsed`
    )
  }
  if (counts.capability > 0) {
    parts.push(
      locale === "zh"
        ? `此 target 不支持 ${counts.capability}`
        : `${counts.capability} unsupported on this target`
    )
  }
  if (counts.name > 0) {
    parts.push(
      locale === "zh"
        ? `名称不可用 ${counts.name}`
        : `${counts.name} had a reserved or unrepresentable name`
    )
  }
  const total = counts.parse + counts.capability + counts.name
  if (locale === "zh") {
    return `跳过 ${total} 个节点（${parts.join("，")}）。`
  }
  return `Skipped ${total} nodes (${parts.join(", ")}).`
}
