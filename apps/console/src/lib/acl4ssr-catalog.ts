export const ACL4SSR_PRESETS = {
  online: [
    { file: "ACL4SSR_Online.ini", effect: "adsChinaSplit" },
    { file: "ACL4SSR_Online_AdblockPlus.ini", effect: "adblockPlus" },
    { file: "ACL4SSR_Online_MultiCountry.ini", effect: "multiCountry" },
    { file: "ACL4SSR_Online_NoAuto.ini", effect: "noAuto" },
    { file: "ACL4SSR_Online_NoReject.ini", effect: "noReject" },
  ],
  mini: [
    { file: "ACL4SSR_Online_Mini.ini", effect: "adsChinaSplit" },
    { file: "ACL4SSR_Online_Mini_AdblockPlus.ini", effect: "adblockPlus" },
    { file: "ACL4SSR_Online_Mini_Ai.ini", effect: "ai" },
    { file: "ACL4SSR_Online_Mini_Fallback.ini", effect: "fallback" },
    { file: "ACL4SSR_Online_Mini_MultiCountry.ini", effect: "multiCountry" },
    { file: "ACL4SSR_Online_Mini_MultiMode.ini", effect: "multiMode" },
    { file: "ACL4SSR_Online_Mini_NoAuto.ini", effect: "noAuto" },
  ],
  full: [
    { file: "ACL4SSR_Online_Full.ini", effect: "adsChinaSplit" },
    { file: "ACL4SSR_Online_Full_AdblockPlus.ini", effect: "adblockPlus" },
    { file: "ACL4SSR_Online_Full_Google.ini", effect: "google" },
    { file: "ACL4SSR_Online_Full_MultiMode.ini", effect: "multiMode" },
    { file: "ACL4SSR_Online_Full_Netflix.ini", effect: "netflix" },
    { file: "ACL4SSR_Online_Full_NoAuto.ini", effect: "noAuto" },
  ],
  classic: [
    { file: "ACL4SSR.ini", effect: "adsChinaSplit" },
    { file: "ACL4SSR_AdblockPlus.ini", effect: "adblockPlus" },
    { file: "ACL4SSR_BackCN.ini", effect: "backCN" },
    { file: "ACL4SSR_Mini.ini", effect: "adsChinaSplit" },
    { file: "ACL4SSR_Mini_Fallback.ini", effect: "fallback" },
    { file: "ACL4SSR_Mini_MultiMode.ini", effect: "multiMode" },
    { file: "ACL4SSR_Mini_NoAuto.ini", effect: "noAuto" },
    { file: "ACL4SSR_NoApple.ini", effect: "noApple" },
    { file: "ACL4SSR_NoAuto.ini", effect: "noAuto" },
    { file: "ACL4SSR_NoAuto_NoApple.ini", effect: "noAutoNoApple" },
    {
      file: "ACL4SSR_NoAuto_NoApple_NoMicrosoft.ini",
      effect: "noAutoNoAppleNoMicrosoft",
    },
    { file: "ACL4SSR_NoMicrosoft.ini", effect: "noMicrosoft" },
    { file: "ACL4SSR_WithChinaIp.ini", effect: "withChinaIp" },
    { file: "ACL4SSR_WithChinaIp_WithGFW.ini", effect: "withChinaIpGfw" },
    { file: "ACL4SSR_WithGFW.ini", effect: "withGfw" },
  ],
} as const

export type Acl4ssrFamily = keyof typeof ACL4SSR_PRESETS
export type Acl4ssrPreset = {
  [Family in Acl4ssrFamily]: (typeof ACL4SSR_PRESETS)[Family][number]
}[Acl4ssrFamily]
export type Acl4ssrConfigFile = Acl4ssrPreset["file"]
export type Acl4ssrEffectId = Acl4ssrPreset["effect"]

/** Combobox group order: key order of `ACL4SSR_PRESETS`. */
export const ACL4SSR_FAMILIES = Object.keys(
  ACL4SSR_PRESETS
) as Acl4ssrFamily[]

export function acl4ssrListed(): readonly Acl4ssrPreset[] {
  return ACL4SSR_FAMILIES.flatMap(
    (family) => ACL4SSR_PRESETS[family] as readonly Acl4ssrPreset[]
  )
}

/** Workshop combobox / session selection id for ACL4SSR config presets. */
export type ConfigSelectionId = "none" | "custom" | Acl4ssrConfigFile

export type ConfigPreset =
  | { kind: "none" }
  | { kind: "custom" }
  | { kind: "listed"; file: Acl4ssrConfigFile }

export function acl4ssrConfigUrl(file: Acl4ssrConfigFile): string {
  return `https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/${file}`
}

export function acl4ssrConfigLabel(file: Acl4ssrConfigFile): string {
  return file.endsWith(".ini") ? file.slice(0, -".ini".length) : file
}

export const ACL4SSR_ONLINE_URL = acl4ssrConfigUrl("ACL4SSR_Online.ini")

const ACL4SSR_PRESET_BY_URL = new Map<string, ConfigPreset>()
for (const preset of acl4ssrListed()) {
  ACL4SSR_PRESET_BY_URL.set(acl4ssrConfigUrl(preset.file), {
    kind: "listed",
    file: preset.file,
  })
}

export function configPresetOf(configUrl: string): ConfigPreset {
  const trimmed = configUrl.trim()
  if (trimmed.length === 0) {
    return { kind: "none" }
  }
  return ACL4SSR_PRESET_BY_URL.get(trimmed) ?? { kind: "custom" }
}

export function configSelectionId(
  preset: ConfigPreset,
  pickingCustom: boolean
): ConfigSelectionId {
  if (pickingCustom || preset.kind === "custom") {
    return "custom"
  }
  if (preset.kind === "none") {
    return "none"
  }
  return preset.file
}
