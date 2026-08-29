import type { Target } from "./service-contract.ts"

const CLASH_CONSUMERS = [
  "Clash Verge Rev",
  "FlClash",
  "Clash Meta for Android",
  "Stash",
  "OpenClash",
  "Karing",
  "Hiddify",
] as const

export const TARGET_CONSUMERS: Record<Target, readonly string[]> = {
  clash: CLASH_CONSUMERS,
  mihomo: CLASH_CONSUMERS,
  quanx: ["Quantumult X"],
  singbox: [
    "SFA",
    "SFI/SFM",
    "GUI.for.sing-box",
    "Throne",
    "Karing",
    "Hiddify",
    "NekoBox",
  ],
  loon: ["Loon"],
  egern: ["Egern"],
  surge: ["Surge", "Surfboard"],
}

export function targetConsumers(target: Target): readonly string[] {
  return TARGET_CONSUMERS[target]
}
