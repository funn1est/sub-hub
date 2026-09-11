import sitemap from "@astrojs/sitemap"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from "astro/config"

export default defineConfig({
  site:
    process.env.ASTRO_SITE ??
    process.env.CF_PAGES_URL ??
    "http://127.0.0.1:4321",
  trailingSlash: "always",
  i18n: {
    defaultLocale: "en",
    locales: ["en", "zh-cn"],
    routing: {
      prefixDefaultLocale: false,
    },
  },
  integrations: [
    sitemap({
      filter: (page) => !page.endsWith("robots.txt"),
      i18n: {
        defaultLocale: "en",
        locales: {
          en: "en",
          "zh-cn": "zh-CN",
        },
      },
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
})
