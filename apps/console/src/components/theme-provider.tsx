import * as React from "react"

import type { Theme } from "@/lib/persist.ts"

type ResolvedTheme = "dark" | "light"

const COLOR_SCHEME_QUERY = "(prefers-color-scheme: dark)"

function getSystemTheme(): ResolvedTheme {
  if (window.matchMedia(COLOR_SCHEME_QUERY).matches) {
    return "dark"
  }
  return "light"
}

function disableTransitionsTemporarily() {
  const root = document.documentElement
  root.classList.add("theme-switching")

  return () => {
    window.getComputedStyle(document.body)
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        root.classList.remove("theme-switching")
      })
    })
  }
}

export function ThemeProvider({
  theme,
  children,
}: {
  theme: Theme
  children: React.ReactNode
}) {
  const applyTheme = React.useCallback((nextTheme: Theme) => {
    const root = document.documentElement
    const resolvedTheme = nextTheme === "system" ? getSystemTheme() : nextTheme
    const restoreTransitions = disableTransitionsTemporarily()
    root.classList.remove("light", "dark")
    root.classList.add(resolvedTheme)
    restoreTransitions()
  }, [])

  React.useEffect(() => {
    applyTheme(theme)
    if (theme !== "system") {
      return undefined
    }

    const mediaQuery = window.matchMedia(COLOR_SCHEME_QUERY)
    const handleChange = () => {
      applyTheme("system")
    }
    mediaQuery.addEventListener("change", handleChange)
    return () => {
      mediaQuery.removeEventListener("change", handleChange)
    }
  }, [theme, applyTheme])

  return children
}
