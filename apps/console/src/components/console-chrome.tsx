import { MonitorIcon, MoonIcon, SunIcon } from "lucide-react"

import { Button } from "@/components/ui/button.tsx"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.tsx"
import { t } from "@/lib/i18n.ts"
import type { Locale, Theme } from "@/lib/persist.ts"

type ConsoleChromeBarProps = {
  locale: Locale
  theme: Theme
  onLocaleChange: (locale: Locale) => void
  onThemeChange: (theme: Theme) => void
}

/** Console chrome: product title plus locale/theme. App owns the state. */
export function ConsoleChromeBar({
  locale,
  theme,
  onLocaleChange,
  onThemeChange,
}: ConsoleChromeBarProps) {
  const copy = t(locale)
  return (
    <header className="sticky top-0 z-10 border-b bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex w-full max-w-3xl items-center justify-between gap-3 px-6 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <img
            src="/icon.svg"
            alt=""
            className="size-9 rounded-[10px] ring-1 ring-foreground/10"
          />
          <div className="min-w-0">
            <h1 className="truncate font-heading text-base font-medium tracking-tight">
              {copy.title}
            </h1>
            <p className="hidden truncate text-xs text-muted-foreground sm:block">
              {copy.tagline}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <LocaleMenu
            label={copy.language}
            locale={locale}
            onChange={onLocaleChange}
          />
          <ThemeMenu
            label={copy.theme}
            theme={theme}
            system={copy.themeSystem}
            light={copy.themeLight}
            dark={copy.themeDark}
            onChange={onThemeChange}
          />
        </div>
      </div>
    </header>
  )
}

function LocaleMenu({
  label,
  locale,
  onChange,
}: {
  label: string
  locale: Locale
  onChange: (locale: Locale) => void
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
        {locale === "zh" ? "中文" : "EN"}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-36">
        <DropdownMenuGroup>
          <DropdownMenuLabel>{label}</DropdownMenuLabel>
          <DropdownMenuRadioGroup
            value={locale}
            onValueChange={(value) => {
              if (value === "zh" || value === "en") {
                onChange(value)
              }
            }}
          >
            <DropdownMenuRadioItem value="zh">中文</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="en">English</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function ThemeMenu({
  label,
  theme,
  system,
  light,
  dark,
  onChange,
}: {
  label: string
  theme: Theme
  system: string
  light: string
  dark: string
  onChange: (theme: Theme) => void
}) {
  const Icon =
    theme === "light" ? SunIcon : theme === "dark" ? MoonIcon : MonitorIcon
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="outline" size="icon-sm" />}>
        <Icon />
        <span className="sr-only">{label}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-36">
        <DropdownMenuGroup>
          <DropdownMenuLabel>{label}</DropdownMenuLabel>
          <DropdownMenuRadioGroup
            value={theme}
            onValueChange={(value) => {
              if (value === "system" || value === "light" || value === "dark") {
                onChange(value)
              }
            }}
          >
            <DropdownMenuRadioItem value="system">
              {system}
            </DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="light">{light}</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="dark">{dark}</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
