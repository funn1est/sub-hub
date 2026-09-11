export const SOURCE_REPO = "https://github.com/funn1est/sub-hub"
export const SOURCE_LICENSE = `${SOURCE_REPO}/blob/main/LICENSE`
export const RELEASES_URL = `${SOURCE_REPO}/releases`
export const DEPLOY_HREF =
  "https://deploy.workers.cloudflare.com/?url=https://github.com/funn1est/sub-hub"
export const DEPLOY_BUTTON_SRC = "https://deploy.workers.cloudflare.com/button"

export type SiteLocale = "en" | "zh-cn"

export type NamedItem = {
  name: string
  detail: string
}

export type TargetItem = {
  token: string
  format: string
  clients: string
}

export type RunItem = {
  title: string
  body: string
}

export type Copy = {
  htmlLang: string
  ogLocale: string
  otherLocaleLabel: string
  title: string
  description: string
  skipToContent: string
  brand: string
  languageNav: string
  tagline: string
  noPublicInstance: string
  heroLead: string
  ctaRepo: string
  ctaReleases: string
  ctaDeployHint: string
  ctaDeployAlt: string
  inputsTitle: string
  inputsLead: string
  inputs: NamedItem[]
  policyTitle: string
  policyItems: string[]
  outputsTitle: string
  outputsLead: string
  outputs: TargetItem[]
  workshopTitle: string
  workshopLead: string
  workshopItems: string[]
  runTitle: string
  runLead: string
  runItems: RunItem[]
  httpTitle: string
  httpLead: string
  httpRoutes: string[]
  httpNotes: string[]
  notTitle: string
  notItems: string[]
  licenseTitle: string
  licenseBody: string
  sourceLink: string
  footerNote: string
}
