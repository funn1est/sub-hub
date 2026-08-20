export const ACL4SSR_ONLINE_FILES = [
  "ACL4SSR_Online.ini",
  "ACL4SSR_Online_AdblockPlus.ini",
  "ACL4SSR_Online_MultiCountry.ini",
  "ACL4SSR_Online_NoAuto.ini",
  "ACL4SSR_Online_NoReject.ini",
] as const

export const ACL4SSR_MINI_FILES = [
  "ACL4SSR_Online_Mini.ini",
  "ACL4SSR_Online_Mini_AdblockPlus.ini",
  "ACL4SSR_Online_Mini_Ai.ini",
  "ACL4SSR_Online_Mini_Fallback.ini",
  "ACL4SSR_Online_Mini_MultiCountry.ini",
  "ACL4SSR_Online_Mini_MultiMode.ini",
  "ACL4SSR_Online_Mini_NoAuto.ini",
] as const

export const ACL4SSR_FULL_FILES = [
  "ACL4SSR_Online_Full.ini",
  "ACL4SSR_Online_Full_AdblockPlus.ini",
  "ACL4SSR_Online_Full_Google.ini",
  "ACL4SSR_Online_Full_MultiMode.ini",
  "ACL4SSR_Online_Full_Netflix.ini",
  "ACL4SSR_Online_Full_NoAuto.ini",
] as const

export type Acl4ssrConfigFile =
  | (typeof ACL4SSR_ONLINE_FILES)[number]
  | (typeof ACL4SSR_MINI_FILES)[number]
  | (typeof ACL4SSR_FULL_FILES)[number]

export type ConfigPreset =
  | { kind: "none" }
  | { kind: "online"; file: (typeof ACL4SSR_ONLINE_FILES)[number] }
  | { kind: "mini"; file: (typeof ACL4SSR_MINI_FILES)[number] }
  | { kind: "full"; file: (typeof ACL4SSR_FULL_FILES)[number] }
  | { kind: "custom" }

export function acl4ssrConfigUrl(file: Acl4ssrConfigFile): string {
  return `https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/${file}`
}

export function acl4ssrConfigLabel(file: Acl4ssrConfigFile): string {
  return file.endsWith(".ini") ? file.slice(0, -".ini".length) : file
}

export const ACL4SSR_ONLINE_URL = acl4ssrConfigUrl("ACL4SSR_Online.ini")

const ACL4SSR_PRESET_BY_URL = new Map<
  string,
  Exclude<ConfigPreset, { kind: "none" } | { kind: "custom" }>
>()
for (const file of ACL4SSR_ONLINE_FILES) {
  ACL4SSR_PRESET_BY_URL.set(acl4ssrConfigUrl(file), { kind: "online", file })
}
for (const file of ACL4SSR_MINI_FILES) {
  ACL4SSR_PRESET_BY_URL.set(acl4ssrConfigUrl(file), { kind: "mini", file })
}
for (const file of ACL4SSR_FULL_FILES) {
  ACL4SSR_PRESET_BY_URL.set(acl4ssrConfigUrl(file), { kind: "full", file })
}

export function clashInstallUrl(subscriptionUrl: string): string {
  return `clash://install-config?url=${encodeURIComponent(subscriptionUrl)}`
}

export function configPresetOf(configUrl: string): ConfigPreset {
  const trimmed = configUrl.trim()
  if (trimmed.length === 0) {
    return { kind: "none" }
  }
  return ACL4SSR_PRESET_BY_URL.get(trimmed) ?? { kind: "custom" }
}
